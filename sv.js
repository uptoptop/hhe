import http from 'node:http';
import { Readable } from 'node:stream';
import { webcrypto as crypto } from 'node:crypto';

// ============================================
// CẤU HÌNH
// ============================================
const PORT = process.env.PORT || 3000;
const STREAM_SECRET = process.env.STREAM_SECRET || ''; // PHẢI trùng với STREAM_SECRET bên sv1
const DEBUG = process.env.DEBUG === 'true';

const FALLBACK_URL = process.env.FALLBACK_URL
  || 'https://huggingface.co/datasets/hiepp2/tvp4/resolve/main/xnxx.mp4';

const STREAM_SIG_HEX_LEN = 32;

if (!STREAM_SECRET && DEBUG) {
  console.warn('[WARN] STREAM_SECRET chưa được cấu hình — mọi request sẽ bị từ chối.');
}

// Lưới an toàn cuối cùng: log lỗi thay vì để process chết đột ngột.
process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT EXCEPTION]', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[UNHANDLED REJECTION]', reason);
});


// (Đã bỏ getDynamicConfig/chunk-splitting — xem giải thích ở phần PROXY PASS-THROUGH bên dưới)

// ============================================
// XÁC MINH CHỮ KÝ (giống hệt thuật toán bên sv1 generateStreamUrl)
// ============================================

function safeEqualHex(left, right) {
  if (!left || !right || left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return diff === 0;
}

/**
 * Trả về { valid, expPlain }. expPlain dùng để tính TTL khoá IP bên dưới.
 */
async function verifyStreamSig(filename, searchParams) {
  const sig = searchParams.get('phim');
  const encExp = searchParams.get('4k');
  if (!sig || !encExp || sig.length !== STREAM_SIG_HEX_LEN || encExp.length !== 8) {
    return { valid: false, expPlain: null };
  }
  if (!STREAM_SECRET) return { valid: false, expPlain: null };

  const encoder = new TextEncoder();
  const now = Math.floor(Date.now() / 1000);

  const cryptoKey = await crypto.subtle.importKey(
    'raw', encoder.encode(STREAM_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const expMask = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode('otp-exp-mask'))).slice(0, 4);
  const expBytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) expBytes[i] = parseInt(encExp.slice(i * 2, i * 2 + 2), 16) ^ expMask[i];
  const expPlain = (((expBytes[0] << 24) | (expBytes[1] << 16) | (expBytes[2] << 8) | expBytes[3]) >>> 0);

  if (now > expPlain) return { valid: false, expPlain: null };

  const expectedBytes = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(`${filename}:${expPlain}`));
  const expectedSig = Array.from(new Uint8Array(expectedBytes)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, STREAM_SIG_HEX_LEN);

  return { valid: safeEqualHex(sig.toLowerCase(), expectedSig), expPlain };
}

// ============================================
// PROXY PASS-THROUGH — 1 lệnh fetch duy nhất, KHÔNG tách chunk/tải song song.
// (Cơ chế tách chunk cũ được thiết kế riêng để né giới hạn subrequest của
// Cloudflare Workers — không cần thiết trên Node.js/Railway, và chính là
// nguyên nhân RAM tăng vọt khi nhiều người xem cùng lúc: mỗi người giữ 3-4
// buffer 2-6MB trong RAM cùng lúc. Giờ mỗi kết nối chỉ giữ 1 stream đang
// chảy qua, RAM gần như không phụ thuộc dung lượng file hay số người xem.)
// ============================================

async function proxyDynamic206(targetUrl, req) {
  const baseHeadersObj = {
    'User-Agent': 'huggingface_hub/0.25.0 hf-xet/0.1.0 python/3.10',
    'X-Xet-Cas-Uid': 'public'
  };
  const clientRange = req.headers['range'];
  const headers = { ...baseHeadersObj };
  if (clientRange) headers.Range = clientRange;

  const resp = await fetch(targetUrl, { method: 'GET', headers, redirect: 'follow' });

  if (!resp.ok && resp.status !== 206) {
    resp.body?.cancel().catch(() => {});
    return { status: 404, statusText: 'Not Found', headers: new Headers(), text: 'Target file not found' };
  }

  const responseHeaders = buildResponseHeaders(resp.headers, targetUrl);
  responseHeaders.set('Accept-Ranges', 'bytes');

  return { status: resp.status, statusText: resp.statusText, headers: responseHeaders, webStream: resp.body };
}

async function fetchStandard(targetUrl, headers, originalUrl) {
  const resp = await fetch(targetUrl, { headers, method: 'GET', redirect: 'follow' });
  if (!resp.ok && resp.status !== 206) {
    return { status: 404, statusText: 'Not Found', headers: new Headers(), text: 'Target file not found' };
  }
  const responseHeaders = buildResponseHeaders(resp.headers, originalUrl);
  return { status: resp.status, statusText: resp.statusText, headers: responseHeaders, webStream: resp.body };
}

function buildResponseHeaders(sourceHeaders, originalUrl) {
  const responseHeaders = new Headers(sourceHeaders);
  const downloadFilename = getDownloadFilename(originalUrl);

  responseHeaders.set('Access-Control-Allow-Origin', '*');
  responseHeaders.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  responseHeaders.set('Access-Control-Allow-Headers', 'Range, Content-Type, User-Agent');
  responseHeaders.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');
  responseHeaders.set('Accept-Ranges', 'bytes');
  responseHeaders.set('Content-Disposition', `inline; filename="${downloadFilename}"; filename*=UTF-8''${encodeURIComponent(downloadFilename)}`);

  if (!responseHeaders.has('Content-Type') || responseHeaders.get('Content-Type') === 'application/octet-stream') {
    responseHeaders.set('Content-Type', downloadFilename.endsWith('.mkv') ? 'video/x-matroska' : 'video/mp4');
  }
  return responseHeaders;
}

function getDownloadFilename(targetUrl) {
  try {
    const pathname = new URL(targetUrl).pathname;
    return pathname.split('/').pop() || 'video.mp4';
  } catch (_) {
    return 'video.mp4';
  }
}

// ============================================
// HTTP SERVER (Node) — thay cho export default { fetch } của Cloudflare
// ============================================

function sendWebResult(res, result) {
  res.writeHead(result.status, result.statusText, Object.fromEntries(result.headers.entries()));
  if (result.text !== undefined) {
    res.end(result.text);
    return;
  }
  if (result.webStream) {
    Readable.fromWeb(result.webStream).pipe(res);
    return;
  }
  res.end();
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
        'Access-Control-Allow-Headers': 'Range, Content-Type, User-Agent',
        'Access-Control-Max-Age': '86400'
      });
      res.end();
      return;
    }

    if (url.pathname === '/health' || url.pathname === '/ping') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', time: Date.now() }));
      return;
    }

    const fullFilename = url.pathname.replace(/^\/+/, '');
    if (!fullFilename) {
      res.writeHead(400);
      res.end('Bad Request: No filename provided.');
      return;
    }

    const filename = fullFilename.split('.')[0];

    // Chỉ chấp nhận request có chữ ký "phim" + "4k" hợp lệ do sv1 tạo ra.
    const sigCheck = await verifyStreamSig(filename, url.searchParams);
    if (!sigCheck.valid) {
      if (DEBUG) console.warn(`[SIG REJECTED] ${filename}`);
      res.writeHead(403);
      res.end('Forbidden: invalid or missing signature');
      return;
    }

    const apiUrl = `https://f.apip4k.dpdns.org/xl.php?${filename}`;
    let targetUrl;
    try {
      const apiResp = await fetch(apiUrl);
      if (!apiResp.ok) {
        targetUrl = FALLBACK_URL;
      } else {
        const rawTargetUrl = (await apiResp.text()).trim();
        if (!rawTargetUrl) {
          targetUrl = FALLBACK_URL;
        } else {
          const targetUrlObj = new URL(rawTargetUrl);
          url.searchParams.forEach((value, key) => targetUrlObj.searchParams.set(key, value));
          targetUrl = targetUrlObj.toString();
        }
      }
    } catch (_) {
      targetUrl = FALLBACK_URL;
    }

    try {
      const result = await proxyDynamic206(targetUrl, req);
      sendWebResult(res, result);
    } catch (err) {
      if (DEBUG) console.error(`[PROXY ERROR] ${err.message}`);
      const fallbackHeaders = {
        'User-Agent': 'huggingface_hub/0.25.0 hf-xet/0.1.0 python/3.10',
        'X-Xet-Cas-Uid': 'public'
      };
      if (req.headers['range']) fallbackHeaders.Range = req.headers['range'];
      const result = await fetchStandard(targetUrl, fallbackHeaders, targetUrl);
      sendWebResult(res, result);
    }
  } catch (err) {
    console.error(`[SERVER ERROR] ${err.stack || err.message}`);
    if (!res.headersSent) {
      res.writeHead(500);
      res.end('Internal Server Error');
    }
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`sv2 (Railway) đang chạy ở port ${PORT}`);
});
