// jimeng-proxy-node/index.js

require('dotenv').config(); // 确保加载 .env 文件中的环境变量

const express = require('express');
const crypto = require('crypto'); // Node.js 内置的加密模块
const util = require('util');
const url = require('url');
const fetch = require('node-fetch'); // 引入 node-fetch
const qs = require('querystring'); // 引入 querystring

const app = express();
const PORT = process.env.PORT || 3000; // 代理服务将监听的端口，默认为 3000

// 中间件：解析 JSON 格式的请求体
app.use(express.json());

// CORS 头部设置：允许跨域请求。
// 在生产环境中，您应该将 'Access-Control-Allow-Origin' 限制为您的前端域名。
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// 从环境变量中获取即梦 API 密钥
const JIMENG_ACCESS_KEY_ID = process.env.JIMENG_ACCESS_KEY_ID;
const JIMENG_SECRET_ACCESS_KEY = process.env.JIMENG_SECRET_ACCESS_KEY;

// 即梦 API 的固定参数
const JIMENG_API_URL = 'https://visual.volcengineapi.com';
const SERVICE = 'cv';
const REGION = 'cn-north-1'; // 官方示例中使用的是 'cn-beijing'，但即梦API文档通常是 'cn-north-1'，这里保持一致
const ACTION = 'CVProcess';
const VERSION = '2022-08-31';

// --- 官方提供的 SigV4 辅助函数 ---

const debuglog = util.debuglog('signer');
const Buffer = require("buffer").Buffer;

/**
 * 不参与加签过程的 header key
 */
const HEADER_KEYS_TO_IGNORE = new Set([
    "authorization",
    "content-type",
    "content-length",
    "user-agent",
    "presigned-expires",
    "expect",
]);

function sign(params) {
    const {
        headers = {},
        query = {},
        region = '',
        serviceName = '',
        method = '',
        pathName = '/',
        accessKeyId = '',
        secretAccessKey = '',
        needSignHeaderKeys = [],
        bodySha,
    } = params;
    const datetime = headers["X-Date"];
    const date = datetime.substring(0, 8); // YYYYMMDD
    // 创建正规化请求
    const [signedHeaders, canonicalHeaders] = getSignHeaders(headers, needSignHeaderKeys);
    const canonicalRequest = [
        method.toUpperCase(),
        pathName,
        queryParamsToString(query) || '',
        `${canonicalHeaders}\n`,
        signedHeaders,
        bodySha || hash(''),
    ].join('\n');
    const credentialScope = [date, region, serviceName, "request"].join('/');
    // 创建签名字符串
    const stringToSign = ["HMAC-SHA256", datetime, credentialScope, hash(canonicalRequest)].join('\n');
    // 计算签名
    const kDate = hmac(secretAccessKey, date);
    const kRegion = hmac(kDate, region);
    const kService = hmac(kRegion, serviceName);
    const kSigning = hmac(kService, "request");
    const signature = hmac(kSigning, stringToSign).toString('hex');
    debuglog('--------CanonicalString:\n%s\n--------SignString:\n%s', canonicalRequest, stringToSign);
    return [
        "HMAC-SHA256",
        `Credential=${accessKeyId}/${credentialScope},`,
        `SignedHeaders=${signedHeaders},`,
        `Signature=${signature}`,
    ].join(' ');
}

function hmac(secret, s) {
    return crypto.createHmac('sha256', secret).update(s, 'utf8').digest();
}

function hash(s) {
    return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function queryParamsToString(params) {
    return Object.keys(params)
        .sort()
        .map((key) => {
            const val = params[key];
            if (typeof val === 'undefined' || val === null) {
                return undefined;
            }
            const escapedKey = uriEscape(key);
            if (!escapedKey) {
                return undefined;
            }
            if (Array.isArray(val)) {
                return `${escapedKey}=${val.map(uriEscape).sort().join(`&${escapedKey}=`)}`;
            }
            return `${escapedKey}=${uriEscape(val)}`;
        })
        .filter((v) => v)
        .join('&');
}

function getSignHeaders(originHeaders, needSignHeaders) {
    function trimHeaderValue(header) {
        return header.toString?.().trim().replace(/\s+/g, ' ') ?? '';
    }
    let h = Object.keys(originHeaders);
    // 根据 needSignHeaders 过滤
    if (Array.isArray(needSignHeaders)) {
        const needSignSet = new Set([...needSignHeaders, 'x-date', 'host'].map((k) => k.toLowerCase()));
        h = h.filter((k) => needSignSet.has(k.toLowerCase()));
    }
    // 根据 ignore headers 过滤
    h = h.filter((k) => !HEADER_KEYS_TO_IGNORE.has(k.toLowerCase()));
    const signedHeaderKeys = h
        .slice()
        .map((k) => k.toLowerCase())
        .sort()
        .join(';');
    const canonicalHeaders = h
        .sort((a, b) => (a.toLowerCase() < b.toLowerCase() ? -1 : 1))
        .map((k) => `${k.toLowerCase()}:${trimHeaderValue(originHeaders[k])}`)
        .join('\n');
    return [signedHeaderKeys, canonicalHeaders];
}

function uriEscape(str) {
    try {
        return encodeURIComponent(str)
            .replace(/[^A-Za-z0-9_.~\-%]+/g, escape)
            .replace(/[*]/g, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`);
    } catch (e) {
        return '';
    }
}

function getDateTimeNow() {
    const now = new Date();
    return now.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

// 获取 body sha256
function getBodySha(body) {
    const hash = crypto.createHash('sha256');
    if (typeof body === 'string') {
        hash.update(body);
    } else if (body instanceof url.URLSearchParams) {
        hash.update(body.toString());
    } else if (Buffer.isBuffer(body)) {
        hash.update(body);
    }
    return hash.digest('hex');
}

// --- Exponential Backoff Retry Function ---
const MAX_RETRIES = 0;
const INITIAL_RETRY_DELAY_MS = 500; // 0.5 seconds

async function makeJimengRequestWithRetry(requestUrl, requestOptions, attempt = 1) {
    try {
        console.log(`[Retry] Attempt ${attempt}/${MAX_RETRIES}: Making request to Jimeng API at ${requestUrl}`);
        const jimengResponse = await fetch(requestUrl, requestOptions);

        if (!jimengResponse.ok) {
            const errorText = await jimengResponse.text();
            console.error(`[Retry] Jimeng API Error (Attempt ${attempt}): Status ${jimengResponse.status}, Response: ${errorText}`);

            // Check for 429 (Too Many Requests) or other retryable errors if applicable
            // For now, only retry on 429
            if (jimengResponse.status === 429 && attempt < MAX_RETRIES) {
                const delay = INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt - 1);
                console.log(`[Retry] Retrying in ${delay}ms due to 429 Too Many Requests... (Attempt ${attempt + 1}/${MAX_RETRIES})`);
                await new Promise(resolve => setTimeout(resolve, delay));
                return makeJimengRequestWithRetry(requestUrl, requestOptions, attempt + 1);
            } else {
                // Re-throw if not 429 or max retries reached
                throw new Error(`Jimeng API call failed with status ${jimengResponse.status}: ${errorText}`);
            }
        }

        const contentType = jimengResponse.headers.get('Content-Type');
        if (!contentType || !contentType.includes('application/json')) {
            const responseText = await jimengResponse.text();
            console.error(`[Retry] Jimeng API returned non-JSON content (Attempt ${attempt}, Content-Type: ${contentType}): ${responseText}`);
            throw new Error(`Jimeng API returned non-JSON content: ${responseText}`);
        }

        const result = await jimengResponse.json();
        console.log(`[Retry] Jimeng API Response (Attempt ${attempt}):`, result);
        return result;

    } catch (error) {
        console.error(`[Retry] Request failed (Attempt ${attempt}):`, error.message);
        throw error; // Re-throw the error after logging
    }
}


// --- 代理服务接口 ---

// 处理来自 Supabase Edge Function 的图片生成请求
app.post('/generate-image', async (req, res) => {
    // 在这里添加 console.log，确认请求已到达代理服务
    console.log('--- Incoming Request ---');
    console.log('Vercel 代理服务已接收到 /generate-image 请求！'); 
    console.log('Request Body:', JSON.stringify(req.body, null, 2));

    // 检查即梦 API 密钥是否已配置
    if (!JIMENG_ACCESS_KEY_ID || !JIMENG_SECRET_ACCESS_KEY) {
        console.error('即梦 API 密钥未在环境变量中配置。');
        return res.status(500).json({ error: '即梦 API 密钥未在代理服务器上配置。' });
    }

    try {
        const requestData = req.body; // 这是从 Supabase Edge Function 转发过来的请求体

        // 确保 width 和 height 在 [256, 768] 范围内，默认为 512
        const requestedWidth = Math.min(Math.max(requestData.width || 512, 256), 768);
        const requestedHeight = Math.min(Math.max(requestData.height || 512, 256), 768);

        // 构造发送给即梦 API 的请求体
        const bodyParams = {
            req_key: "jimeng_high_aes_general_v21_L", // 根据即梦 API 文档确定
            prompt: requestData.prompt,
            seed: requestData.seed || -1,
            width: requestedWidth,
            height: requestedHeight,
            use_pre_llm: true, // 根据即梦 API 文档确定
            use_sr: true, // 默认开启超分
            return_url: true, // 官方示例中包含此项
        };
        console.log('Constructed Jimeng API Request Body:', JSON.stringify(bodyParams, null, 2));

        const bodyString = JSON.stringify(bodyParams);
        const datetime = getDateTimeNow();

        // 构造用于签名的参数
        const signParams = {
            headers: {
                "X-Date": datetime,
                "Content-Type": "application/json",
                "Host": JIMENG_API_URL.replace('https://', ''), // Host 头部不包含协议
            },
            method: 'POST',
            query: {
                Version: VERSION,
                Action: ACTION,
            },
            accessKeyId: JIMENG_ACCESS_KEY_ID,
            secretAccessKey: JIMENG_SECRET_ACCESS_KEY,
            serviceName: SERVICE,
            region: REGION,
            bodySha: getBodySha(bodyString),
            pathName: '/', // 即梦 API 的路径通常是根路径
        };
        console.log('Signing Parameters:', JSON.stringify(signParams, null, 2));

        // 正规化 query object， 防止串化后出现 query 值为 undefined 情况
        for (const [key, val] of Object.entries(signParams.query)) {
            if (val === undefined || val === null) {
                signParams.query[key] = '';
            }
        }

        const authorization = sign(signParams);
        console.log('Generated Authorization Header:', authorization);

        // 发起对即梦 API 的实际请求 (使用重试逻辑)
        const jimengResult = await makeJimengRequestWithRetry(
            `${JIMENG_API_URL}/?${qs.stringify(signParams.query)}`,
            {
                headers: {
                    ...signParams.headers, // 包含 Content-Type, Host, X-Date
                    'Authorization': authorization, // 添加生成的签名
                },
                method: signParams.method,
                body: bodyString,
            }
        );

        // 检查即梦 API 返回的业务错误
        if (jimengResult.code !== 10000) { // 文档中成功状态码是10000
            console.error('即梦 API 业务错误:', jimengResult.message, 'Details:', jimengResult);
            return res.status(500).json({ error: jimengResult.message || '即梦 API 业务错误', details: jimengResult });
        }

        // 成功响应，根据文档从 image_urls 数组中获取第一个 URL
        if (jimengResult.data && jimengResult.data.image_urls && jimengResult.data.image_urls.length > 0) {
            const imageUrl = jimengResult.data.image_urls[0];
            console.log('Successfully generated image URL:', imageUrl);
            return res.status(200).json({ success: true, imageUrl: imageUrl });
        } else {
            console.error('Jimeng API response did not contain image URL:', jimengResult);
            throw new Error('即梦 API 响应中未找到图片URL');
        }

    } catch (error) {
        console.error('Node.js 代理服务内部错误:', error.message);
        // 统一错误响应格式
        res.status(500).json({ error: '代理服务内部错误', details: error.message });
    } finally {
        console.log('--- Request Processing Complete ---');
    }
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`Node.js 代理服务正在监听端口 ${PORT}`);
    console.log(`请确保在部署环境中设置了 JIMENG_ACCESS_KEY_ID 和 JIMENG_SECRET_ACCESS_KEY 环境变量。`);

    // 在这里添加 console.log，确认服务已成功启动
    console.log('Vercel 代理服务已成功启动并监听请求！'); 
});
