const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_RETRY = Object.freeze({
    limit: 0,
    methods: ['GET', 'PUT', 'HEAD', 'DELETE', 'OPTIONS', 'TRACE'],
    statusCodes: [408, 413, 429, 500, 502, 503, 504, 521, 522, 524],
    errorCodes: [
        'ETIMEDOUT',
        'ECONNRESET',
        'EADDRINUSE',
        'ECONNREFUSED',
        'EPIPE',
        'ENOTFOUND',
        'ENETUNREACH',
        'EAI_AGAIN',
    ],
});

const DEFAULT_HEADERS = Object.freeze({
    accept: 'application/json',
    'accept-language': 'en-US',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
});

function toPositiveInteger(value, fallback) {
    const number = Number(value);
    return Number.isSafeInteger(number) && number >= 0 ? number : fallback;
}

function normalizeTimeout(timeout) {
    if (typeof timeout === 'number') {
        return toPositiveInteger(timeout, DEFAULT_TIMEOUT_MS);
    }
    if (timeout && typeof timeout === 'object' && timeout.request !== undefined) {
        return toPositiveInteger(timeout.request, DEFAULT_TIMEOUT_MS);
    }
    return DEFAULT_TIMEOUT_MS;
}

function normalizeRetry(retry = {}) {
    const input = typeof retry === 'number' ? { limit: retry } : retry;
    return {
        limit: toPositiveInteger(input.limit, DEFAULT_RETRY.limit),
        methods: new Set((input.methods ?? DEFAULT_RETRY.methods).map(method => String(method).toUpperCase())),
        statusCodes: new Set((input.statusCodes ?? DEFAULT_RETRY.statusCodes).map(Number)),
        errorCodes: new Set((input.errorCodes ?? DEFAULT_RETRY.errorCodes).map(String)),
        calculateDelay: typeof input.calculateDelay === 'function' ? input.calculateDelay : null,
    };
}

function mergeRetry(base, override) {
    if (override === undefined) return base;
    const input = typeof override === 'number' ? { limit: override } : override;
    return normalizeRetry({
        limit: input.limit ?? base.limit,
        methods: input.methods ?? [...base.methods],
        statusCodes: input.statusCodes ?? [...base.statusCodes],
        errorCodes: input.errorCodes ?? [...base.errorCodes],
        calculateDelay: input.calculateDelay ?? base.calculateDelay,
    });
}

function responseHeaders(headers) {
    const result = Object.fromEntries(headers.entries());
    const cookies = headers.getSetCookie?.();
    if (cookies?.length) result['set-cookie'] = cookies;
    return result;
}

function errorCode(error) {
    let current = error;
    while (current) {
        if (typeof current.code === 'string') return current.code;
        current = current.cause;
    }
    return null;
}

function retryAfterMs(response) {
    const value = response?.headers?.['retry-after'];
    if (value === undefined) return null;

    const seconds = Number(value);
    if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1_000;

    const date = Date.parse(value);
    return Number.isFinite(date) ? Math.max(0, date - Date.now()) : null;
}

function defaultRetryDelay(attemptCount, response) {
    const fromHeader = retryAfterMs(response);
    if (fromHeader !== null) return fromHeader;
    return 2 ** (attemptCount - 1) * 1_000;
}

function makeResponse(raw, body) {
    return {
        body,
        headers: responseHeaders(raw.headers),
        statusCode: raw.status,
        status: raw.status,
        statusMessage: raw.statusText,
        url: raw.url,
    };
}

function httpError(response, method, url) {
    const statusText = response.statusMessage ? ` (${response.statusMessage})` : '';
    const error = new Error(`Request failed with status code ${response.statusCode}${statusText}: ${method} ${url}`);
    error.name = 'HTTPError';
    error.code = 'ERR_NON_2XX_3XX_RESPONSE';
    error.response = response;
    return error;
}

function parseError(cause, response) {
    const error = new Error(`${cause.message} in "${response.url}"`, { cause });
    error.name = 'ParseError';
    error.code = 'ERR_BODY_PARSE_FAILURE';
    error.response = response;
    return error;
}

async function readBody(raw) {
    const text = await raw.text();
    if (!text) return '';

    try {
        return JSON.parse(text);
    } catch (error) {
        if (!raw.ok) return text;
        const response = makeResponse(raw, text);
        throw parseError(error, response);
    }
}

function validateProxyUrl(proxyUrl) {
    if (!proxyUrl) return null;
    const parsed = new URL(proxyUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new TypeError('Authentication proxy URL must use http: or https:.');
    }
    return parsed.href;
}

/**
 * POST transport with parsed response bodies, retries, timeouts, and cancellation.
 * Uses native fetch by default and a matching fetch/ProxyAgent pair for proxies.
 */
export function createAuthHttpClient(options = {}) {
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== 'function') {
        throw new TypeError('Node.js built-in fetch is required.');
    }

    const proxyUrl = validateProxyUrl(options.proxyUrl);
    const defaultTimeout = normalizeTimeout(options.timeout);
    const defaultRetry = normalizeRetry(options.retry);
    const baseHeaders = new Headers(DEFAULT_HEADERS);
    for (const [name, value] of new Headers(options.headers).entries()) {
        baseHeaders.set(name, value);
    }
    let proxyTransportPromise = null;

    async function getTransport() {
        if (!proxyUrl) return { fetch: fetchImpl, dispatcher: undefined };

        proxyTransportPromise ??= import('undici').then(({ fetch: proxyFetch, ProxyAgent }) => ({
            fetch: proxyFetch,
            dispatcher: new ProxyAgent({
                uri: proxyUrl,
                proxyTls: { rejectUnauthorized: true },
                requestTls: { rejectUnauthorized: true },
            }),
        }));
        return proxyTransportPromise;
    }

    async function request(method, url, requestOptions = {}) {
        const upperMethod = method.toUpperCase();
        if (requestOptions.body !== undefined && requestOptions.json !== undefined) {
            throw new TypeError('Specify either body or json, not both.');
        }

        const retry = mergeRetry(defaultRetry, requestOptions.retry);
        const timeoutMs = requestOptions.timeout === undefined
            ? defaultTimeout
            : normalizeTimeout(requestOptions.timeout);
        const headers = new Headers(baseHeaders);
        for (const [name, value] of new Headers(requestOptions.headers).entries()) {
            headers.set(name, value);
        }

        let body = requestOptions.body;
        if (requestOptions.json !== undefined) {
            body = JSON.stringify(requestOptions.json);
            if (!headers.has('content-type')) headers.set('content-type', 'application/json');
        }

        const transport = await getTransport();
        const mayRetry = retry.methods.has(upperMethod);
        let attemptCount = 0;

        while (true) {
            attemptCount += 1;
            const timeoutSignal = timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : null;
            const signal = requestOptions.signal && timeoutSignal
                ? AbortSignal.any([requestOptions.signal, timeoutSignal])
                : requestOptions.signal ?? timeoutSignal ?? undefined;

            let response;
            let caught;
            try {
                const raw = await transport.fetch(url, {
                    method: upperMethod,
                    headers,
                    body,
                    redirect: 'follow',
                    signal,
                    ...(transport.dispatcher ? { dispatcher: transport.dispatcher } : {}),
                });
                const parsedBody = await readBody(raw);
                response = makeResponse(raw, parsedBody);

                if (raw.ok) return response;
                caught = httpError(response, upperMethod, url);
            } catch (error) {
                caught = error;
                response = error.response;
            }

            const abortedByCaller = requestOptions.signal?.aborted;
            const statusRetry = response && retry.statusCodes.has(response.statusCode)
                && (response.statusCode !== 413 || retryAfterMs(response) !== null);
            const networkRetry = !response && (
                caught?.name === 'TimeoutError'
                || retry.errorCodes.has(errorCode(caught))
            );
            const retryable = mayRetry && !abortedByCaller && (statusRetry || networkRetry);

            if (!retryable || attemptCount > retry.limit) throw caught;

            const delay = retry.calculateDelay
                ? retry.calculateDelay({ attemptCount, error: caught, response })
                : defaultRetryDelay(attemptCount, response);
            if (timeoutMs > 0 && retryAfterMs(response) > timeoutMs) throw caught;
            if (delay > 0) await new Promise(resolve => setTimeout(resolve, delay));
        }
    }

    return Object.freeze({
        get: (url, requestOptions) => request('GET', url, requestOptions),
        post: (url, requestOptions) => request('POST', url, requestOptions),
    });
}
