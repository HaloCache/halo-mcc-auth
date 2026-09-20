/**
 * POST transport with parsed response bodies, retries, timeouts, and cancellation.
 * Uses native fetch by default and a matching fetch/ProxyAgent pair for proxies.
 */
export declare function createAuthHttpClient(options?: {}): Readonly<{
    get: (url: any, requestOptions: any) => Promise<{
        body: any;
        headers: {
            [k: string]: any;
        };
        statusCode: any;
        status: any;
        statusMessage: any;
        url: any;
    }>;
    post: (url: any, requestOptions: any) => Promise<{
        body: any;
        headers: {
            [k: string]: any;
        };
        statusCode: any;
        status: any;
        statusMessage: any;
        url: any;
    }>;
}>;
