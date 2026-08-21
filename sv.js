import http from 'node:http';
import { Readable } from 'node:stream';
import { webcrypto as crypto } from 'node:crypto';
import Redis from 'ioredis';

// ============================================
// CẤU HÌNH
// ============================================
const PORT = process.env.PORT || 3000;
const REDIS_URL = process.env.REDIS_URL; // Railway tự cấp khi bạn add plugin Redis
const STREAM_SECRET = process.env.STREAM_SECRET || ''; // PHẢI trùng với STREAM_SECRET bên sv1
const DEBUG = process.env.DEBUG === 'true';
const IS_FREE_PLAN = false;

const FALLBACK_URL = process.env.FALLBACK_URL
  || 'https://huggingface.co/datasets/hiepp2/tvp4/resolve/main/xnxx.mp4';

const STREAM_SIG_HEX_LEN = 32;
const MAX_IPS_PER_LINK = 2;         // 1 link ký được dùng tối đa bởi 2 IP khác nhau (đổi wifi <-> 4G)
const LINK_LOCK_MIN_TTL = 60;       // TTL tối thiểu ghi vào Redis (giây)
const RATE_LIMIT_WINDOW_SEC = 10;   // Cửa sổ rate-limit
const RATE_LIMIT_MAX = 20;          // Tối đa 20 request / 10s / IP

if (!STREAM_SECRET && DEBUG) {
  console.warn('[WARN] STREAM_SECRET chưa được cấu hình — mọi request sẽ bị từ chối.');
}

const redis = REDIS_URL ? new Redis(REDIS_URL) : null;
if (!redis) {
  console.warn('[WARN] REDIS_URL chưa được cấu hình — rate-limit và khoá IP sẽ bị bỏ qua (không chặn).');
}

// ============================================
// LUA SCRIPT (ATOMIC) — chống race condition khi traffic cao.
// Toàn bộ "đọc -> kiểm tra -> ghi" chạy gọn trong 1 lệnh duy nhất trên Redis,
// không thể bị 2 request chen ngang giữa chừng như khi tách GET/SET riêng.
// ============================================

// Rate-limit: INCR + set TTL lần đầu, tất cả trong 1 lệnh atomic.
redis?.defineCommand('rateLimitHit', {
  numberOfKeys: 1,
  lua: `
    local current = redis.call('INCR', KEYS[1])
    if tonumber(current) == 1 then
      redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    return current
  `
});

// Khoá IP theo link: đọc danh sách IP hiện tại, kiểm tra + thêm IP mới (nếu còn chỗ),
// ghi lại — tất cả trong 1 lệnh atomic, không có khoảng hở giữa đọc và ghi.
redis?.defineCommand('lockIpForLink', {
  numberOfKeys: 1,
  lua: `
    local raw = redis.call('GET', KEYS[1])
    local ips = {}
    if raw then
      ips = cjson.decode(raw)
    end

    for i, v in ipairs(ips) do
      if v == ARGV[1] then
        return 1
      end
    end

    if #ips >= tonumber(ARGV[2]) then
      return 0
    end

    table.insert(ips, ARGV[1])
    redis.call('SET', KEYS[1], cjson.encode(ips), 'EX', tonumber(ARGV[3]))
    return 1
  `
});


// ============================================
// CẤU HÌNH TỐI ƯU THEO DUNG LƯỢNG FILE (giữ nguyên logic gốc)
// ============================================
function getDynamicConfig(totalFileSize) {
  const GB = 1024 * 1024 * 1024;

  if (IS_FREE_PLAN) {
    return { chunkSize: 2 * 1024 * 1024, concurrency: 2, maxSubrequests: 40 };
  }
  if (!totalFileSize || totalFileSize < 1 * GB) {
    return { chunkSize: 2 * 1024 * 1024, concurrency: 3, maxSubrequests: 113000 };
  }
  if (totalFileSize <= 10 * GB) {
    return { chunkSize: 3 * 1024 * 1024, concurrency: 4, maxSubrequests: 122000 };
  }
  return { chunkSize: 6 * 1024 * 1024, concurrency: 4, maxSubrequests: 136000 };
}

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
// CHỐNG SHARE LINK / SPAM THEO IP (Redis)
// ============================================

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

async function checkIpRateLimit(ip) {
  if (!redis) return true;
  try {
    // Atomic: INCR + EXPIRE (lần đầu) gộp trong 1 lệnh -> không có khoảng hở race condition
    const count = await redis.rateLimitHit(`rate:${ip}`, RATE_LIMIT_WINDOW_SEC);
    return count <= RATE_LIMIT_MAX;
  } catch (err) {
    if (DEBUG) console.warn(`[RATE LIMIT ERROR] ${err.message}`);
    return true; // lỗi hạ tầng thì không chặn nhầm user hợp lệ
  }
}

async function checkAndLockIp(sig, ip, expPlain) {
  if (!redis) return true;
  const key = `lock:${sig}`;
  const ttl = Math.max(LINK_LOCK_MIN_TTL, expPlain - Math.floor(Date.now() / 1000));

  try {
    // Atomic: đọc + kiểm tra + ghi gộp trong 1 lệnh Lua -> không thể bị 2 IP chen ngang
    // giữa lúc đọc và ghi (khác với get()+set() tách rời trước đây).
    const result = await redis.lockIpForLink(key, ip, MAX_IPS_PER_LINK, ttl);
    if (result === 0 && DEBUG) {
      console.warn(`[IP LOCK] Link bị share vượt giới hạn ${MAX_IPS_PER_LINK} IP: ${key}`);
    }
    return result === 1;
  } catch (err) {
    if (DEBUG) console.warn(`[IP LOCK ERROR] ${err.message}`);
    return true;
  }
}

// ============================================
// PROXY 206 (giữ nguyên logic gốc, chỉ đổi cách trả response cho Node http)
// ============================================

async function proxyDynamic206(targetUrl, req) {
  const baseHeadersObj = {
    'User-Agent': 'huggingface_hub/0.25.0 hf-xet/0.1.0 python/3.10',
    'X-Xet-Cas-Uid': 'public'
  };
  const clientRange = req.headers['range'];

  let headResp = await fetch(targetUrl, { method: 'HEAD', headers: baseHeadersObj, redirect: 'follow' });
  if (!headResp.ok || !headResp.headers.get('content-length')) {
    headResp = await fetch(targetUrl, { method: 'GET', headers: { ...baseHeadersObj, Range: 'bytes=0-0' }, redirect: 'follow' });
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
    try {
      const totalChunks = Math.ceil(requestedSize / chunkSize);
      let nextChunkToFetch = 0;
      let nextChunkToWrite = 0;
      const pendingFetches = new Map();
      const HARD_CAP_PER_CHUNK = chunkSize * 2;

      const launchFetch = (chunkIndex) => {
        const chunkStart = startByte + chunkIndex * chunkSize;
        if (chunkStart > endByte) return null;
        const chunkEnd = Math.min(chunkStart + chunkSize - 1, endByte);
        const headers = { ...baseHeadersObj, Range: `bytes=${chunkStart}-${chunkEnd}` };

        return fetch(finalUrl, { headers, method: 'GET', redirect: 'follow' }).then(res => {
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
        try {
          await res.body.pipeTo(writable, { preventClose: true });
        } catch (err) {
          throw new Error(`Lỗi khi pipe chunk #${chunkIndex}: ${err.message}`);
        }
      };

      while (nextChunkToFetch < concurrency && nextChunkToFetch < totalChunks) {
        pendingFetches.set(nextChunkToFetch, launchFetch(nextChunkToFetch));
        nextChunkToFetch++;
      }

      while (nextChunkToWrite < totalChunks) {
        const currentPromise = pendingFetches.get(nextChunkToWrite);
        if (!currentPromise) break;

        const res = await currentPromise;
        pendingFetches.delete(nextChunkToWrite);

        if (nextChunkToFetch < totalChunks) {
          pendingFetches.set(nextChunkToFetch, launchFetch(nextChunkToFetch));
          nextChunkToFetch++;
        }

        await drainToWriter(res, nextChunkToWrite);
        nextChunkToWrite++;
      }
    } catch (err) {
      if (DEBUG) console.warn(`[PIPELINE ABORTED] ${err.message}`);
    } finally {
      try { await writable.close(); } catch (_) {}
    }
  })();

  const responseHeaders = buildResponseHeaders(headResp.headers, targetUrl);
  responseHeaders.set('Accept-Ranges', 'bytes');
  responseHeaders.set('Content-Range', `bytes ${startByte}-${endByte}/${totalFileSize || '*'}`);
  responseHeaders.set('Content-Length', requestedSize.toString());

  return { status: 206, statusText: 'Partial Content', headers: responseHeaders, webStream: readable };
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
    const clientIp = getClientIp(req);

    // 1. Verify chữ ký phim/4k do sv1 tạo
    const sigCheck = await verifyStreamSig(filename, url.searchParams);
    if (!sigCheck.valid) {
      if (DEBUG) console.warn(`[SIG REJECTED] ${filename} | IP: ${clientIp}`);
      res.writeHead(403);
      res.end('Forbidden: invalid or missing signature');
      return;
    }

    // 2. Rate limit theo IP
    const withinRateLimit = await checkIpRateLimit(clientIp);
    if (!withinRateLimit) {
      res.writeHead(429, { 'Retry-After': '10' });
      res.end('Too Many Requests');
      return;
    }

    // 3. Khoá link theo IP (chống share)
    const sigParam = url.searchParams.get('phim');
    const ipAllowed = await checkAndLockIp(sigParam, clientIp, sigCheck.expPlain);
    if (!ipAllowed) {
      res.writeHead(403);
      res.end('Forbidden: link has been used from too many locations');
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

server.listen(PORT, () => {
  console.log(`sv2 (Railway) đang chạy ở port ${PORT}`);
});
