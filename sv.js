import http from 'node:http';
import { Readable } from 'node:stream';
import { webcrypto as crypto } from 'node:crypto';

// ============================================
// CẤU HÌNH
// ============================================
const PORT = process.env.PORT || 3000;
const STREAM_SECRET = process.env.STREAM_SECRET || ''; // PHẢI trùng với STREAM_SECRET bên sv1
const DEBUG = process.env.DEBUG === 'true';
const IS_FREE_PLAN = false;

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


// ============================================
// CẤU HÌNH TỐI ƯU THEO DUNG LƯỢNG FILE
// ============================================
function getDynamicConfig(totalFileSize) {
  const GB = 1024 * 1024 * 1024;

  if (IS_FREE_PLAN) {
    return { chunkSize: 2 * 1024 * 1024, concurrency: 5, maxSubrequests: 111140 };
  }
  if (!totalFileSize || totalFileSize < 1 * GB) {
    return { chunkSize: 4 * 1024 * 1024, concurrency: 12, maxSubrequests: 113000 };
  }
  if (totalFileSize <= 10 * GB) {
    return { chunkSize: 8 * 1024 * 1024, concurrency: 14, maxSubrequests: 122000 };
  }
  return { chunkSize: 10 * 1024 * 1024, concurrency: 18, maxSubrequests: 136000 };
}

// ============================================
// XÁC MINH CHỮ KÝ
// ============================================

function safeEqualHex(left, right) {
  if (!left || !right || left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return diff === 0;
}

/**
 * Trả về { valid, expPlain }.
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
// PROXY 206 (ĐÃ THÊM ABORT SIGNAL CHỐNG LEAK RAM)
// ============================================

async function proxyDynamic206(targetUrl, req, signal) {
  const baseHeadersObj = {
    'User-Agent': 'huggingface_hub/0.25.0 hf-xet/0.1.0 python/3.10',
    'X-Xet-Cas-Uid': 'public'
  };
  const clientRange = req.headers['range'];

  let headResp = await fetch(targetUrl, { method: 'HEAD', headers: baseHeadersObj, redirect: 'follow', signal });
  if (!headResp.ok || !headResp.headers.get('content-length')) {
    headResp = await fetch(targetUrl, { method: 'GET', headers: { ...baseHeadersObj, Range: 'bytes=0-0' }, redirect: 'follow', signal });
  }

  const finalUrl = headResp.url || targetUrl;

  let totalFileSize = 0;
  const contentRange = headResp.headers.get('content-range');
  if (contentRange) {
    const match = contentRange.match(/\/(\d+)/);
    if (match) totalFileSize = parseInt(match[1], 10);
  }
  if (!totalFileSize) {
    const contentLength = headResp.headers.get('content-length');
    if (contentLength) totalFileSize = parseInt(contentLength, 10);
  }

  const { chunkSize, concurrency, maxSubrequests } = getDynamicConfig(totalFileSize);

  let startByte = 0;
  let endByte = totalFileSize > 0 ? totalFileSize - 1 : 0;

  if (clientRange) {
    const rangeMatch = clientRange.match(/bytes=(\d+)-(\d+)?/);
    if (rangeMatch) {
      startByte = parseInt(rangeMatch[1], 10);
      if (rangeMatch[2]) {
        endByte = parseInt(rangeMatch[2], 10);
      } else if (totalFileSize > startByte) {
        endByte = totalFileSize - 1;
      }
    }
  }

  const maxAllowedBytes = startByte + (maxSubrequests * chunkSize) - 1;
  if (endByte > maxAllowedBytes) endByte = maxAllowedBytes;

  const requestedSize = Math.max(0, (endByte - startByte) + 1);

  const { readable, writable } = new TransformStream();

  (async () => {
    const writer = writable.getWriter();
    // Khai báo NGOÀI try -> để "finally" bên dưới truy cập được. try{} và finally{}
    // là 2 block scope RIÊNG BIỆT trong JS: const/let khai báo trong try KHÔNG
    // được nhìn thấy trong finally -> gây ReferenceError: pendingFetches is not defined
    // (đây chính là lỗi bạn vừa gặp trên Railway).
    const totalChunks = Math.ceil(requestedSize / chunkSize);
    let nextChunkToFetch = 0;
    let nextChunkToWrite = 0;
    const pendingFetches = new Map();
    const HARD_CAP_PER_CHUNK = chunkSize * 2;

    try {
      const launchFetch = (chunkIndex) => {
        const chunkStart = startByte + chunkIndex * chunkSize;
        if (chunkStart > endByte) return null;
        const chunkEnd = Math.min(chunkStart + chunkSize - 1, endByte);
        const headers = { ...baseHeadersObj, Range: `bytes=${chunkStart}-${chunkEnd}` };

        return fetch(finalUrl, { headers, method: 'GET', redirect: 'follow', signal }).then(res => {
          if (res.status !== 206) {
            res.body?.cancel().catch(() => {});
            throw new Error(`Origin không trả 206 cho chunk #${chunkIndex} (status ${res.status})`);
          }
          const declaredLen = parseInt(res.headers.get('content-length') || '0', 10);
          if (declaredLen && declaredLen > HARD_CAP_PER_CHUNK) {
            res.body?.cancel().catch(() => {});
            throw new Error(`Chunk #${chunkIndex} content-length vượt giới hạn an toàn`);
          }
          return res;
        });
      };

      const drainToWriter = async (res, chunkIndex) => {
        if (!res || !res.body) return;
        const reader = res.body.getReader();
        try {
          while (true) {
            if (signal.aborted) throw new Error('Client aborted process');
            const { done, value } = await reader.read();
            if (done) break;
            await writer.write(value);
          }
        } finally {
          reader.releaseLock();
        }
      };

      while (nextChunkToFetch < concurrency && nextChunkToFetch < totalChunks) {
        if (signal.aborted) break;
        pendingFetches.set(nextChunkToFetch, launchFetch(nextChunkToFetch));
        nextChunkToFetch++;
      }

      while (nextChunkToWrite < totalChunks) {
        if (signal.aborted) break;
        const currentPromise = pendingFetches.get(nextChunkToWrite);
        if (!currentPromise) break;

        const res = await currentPromise;
        pendingFetches.delete(nextChunkToWrite);

        if (nextChunkToFetch < totalChunks && !signal.aborted) {
          pendingFetches.set(nextChunkToFetch, launchFetch(nextChunkToFetch));
          nextChunkToFetch++;
        }

        await drainToWriter(res, nextChunkToWrite);
        nextChunkToWrite++;
      }
    } catch (err) {
      if (DEBUG) console.warn(`[PIPELINE ABORTED] ${err.message}`);
    } finally {
      // Dọn dẹp dứt điểm các fetch promise còn đọng lại
      for (const [_, p] of pendingFetches) {
        p.then(res => res?.body?.cancel().catch(() => {})).catch(() => {});
      }
      pendingFetches.clear();
      try { await writer.close(); } catch (_) {}
    }
  })();

  const responseHeaders = buildResponseHeaders(headResp.headers, targetUrl);
  responseHeaders.set('Accept-Ranges', 'bytes');
  responseHeaders.set('Content-Length', requestedSize.toString());

  // Chỉ trả 206 + Content-Range khi client THỰC SỰ gửi Range (đúng chuẩn HTTP).
  // Không có Range -> 200 OK cho toàn bộ nội dung. Nhiều native player (Android
  // ExoPlayer / iOS AVPlayer qua Flutter) strict theo chuẩn này hơn browser.
  if (clientRange) {
    responseHeaders.set('Content-Range', `bytes ${startByte}-${endByte}/${totalFileSize || '*'}`);
    return { status: 206, statusText: 'Partial Content', headers: responseHeaders, webStream: readable };
  }

  return { status: 200, statusText: 'OK', headers: responseHeaders, webStream: readable };
}

async function fetchStandard(targetUrl, headers, originalUrl, signal) {
  const resp = await fetch(targetUrl, { headers, method: 'GET', redirect: 'follow', signal });
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
// HTTP SERVER (NODE) — ĐÃ BỔ SUNG LẮNG NGHE CLIENT CLOSE
// ============================================

function sendWebResult(res, result, signal) {
  res.writeHead(result.status, result.statusText, Object.fromEntries(result.headers.entries()));
  if (result.text !== undefined) {
    res.end(result.text);
    return;
  }
  if (result.webStream) {
    const nodeStream = Readable.fromWeb(result.webStream);

    // Hủy Stream ngay lập tức nếu Abort Signal được bật
    const onAbort = () => {
      nodeStream.destroy();
    };
    signal.addEventListener('abort', onAbort, { once: true });

    nodeStream.on('end', () => {
      signal.removeEventListener('abort', onAbort);
    });

    nodeStream.pipe(res);
    return;
  }
  res.end();
}

const server = http.createServer(async (req, res) => {
  // Tạo Controller riêng cho mỗi Client Request
  const abortController = new AbortController();
  const { signal } = abortController;

  // Khi Client tua / đóng trình duyệt -> hủy ngay các fetch ngầm
  req.on('close', () => {
    if (!res.writableEnded) {
      abortController.abort();
    }
  });

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

    // Xác minh chữ ký phim + 4k
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
      const apiResp = await fetch(apiUrl, { signal });
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

    if (signal.aborted) return;

    try {
      const result = await proxyDynamic206(targetUrl, req, signal);
      sendWebResult(res, result, signal);
    } catch (err) {
      if (signal.aborted) return;
      if (DEBUG) console.error(`[PROXY ERROR] ${err.message}`);
      const fallbackHeaders = {
        'User-Agent': 'huggingface_hub/0.25.0 hf-xet/0.1.0 python/3.10',
        'X-Xet-Cas-Uid': 'public'
      };
      if (req.headers['range']) fallbackHeaders.Range = req.headers['range'];
      const result = await fetchStandard(targetUrl, fallbackHeaders, targetUrl, signal);
      sendWebResult(res, result, signal);
    }
  } catch (err) {
    if (signal.aborted) return;
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
