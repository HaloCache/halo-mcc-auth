/**
 * SISU authentication using the Halo MCC client ID and Win32 device type.
 * Refresh tokens use the `t=` prefix; new tokens use `d=`.
 *
 * Based on work and documentation done by Gamergotten
 *
 * @module sisu-auth
 */
import crypto from 'node:crypto';
export declare class SisuAuth {
    cacheDir: string;
    sessionName: string;
    log: Object;
    xboxKeypair: crypto.webcrypto.CryptoKeyPair | {
        privateKey: crypto.webcrypto.CryptoKey;
        publicKey: crypto.webcrypto.CryptoKey;
    } | null;
    xboxJwk: any;
    sisuSessionId: any;
    pkceCodeVerifier: string | null;
    pkceCodeChallenge: string | null;
    pkceState: string | null;
    msCv: string | null;
    refreshPromise: Promise<any> | null;
    client: Readonly<{
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
    deviceId: any;
    /**
     * @param {Object} options - Configuration options
     * @param {string} [options.cacheDir] - Directory to store auth tokens
     * @param {string} options.sessionName - Filename namespace for cached credentials; independent of account identity.
     * @param {Object} [options.logger] - Custom logger instance
     */
    constructor(options?: {
        cacheDir?: string;
        sessionName: string;
        logger?: Object;
    });
    /**
     * Initialize crypto keypair for device authentication
     * @private
     */
    private _initCrypto;
    /**
     * Generate MS-CV (Microsoft Correlation Vector) header value
     * @private
     */
    private _generateMsCv;
    /**
     * Generate PKCE code verifier and challenge
     * @private
     */
    private _generatePKCE;
    /**
     * Sign an Xbox Live request over its path, query, and UTF-8 payload bytes.
     *
     * @private
     */
    private _sign;
    /**
     * Normalize transport errors to the package's response-error contract.
     * @private
     */
    private _normalizeError;
    /**
     * Get device token (Win32 device type)
     * @private
     */
    private _getDeviceToken;
    /**
     * Get XSTS token for a relying party
     * @private
     */
    private _getXSTSToken;
    _checkTokenError(errorCode: any, response: any): void;
    _loadCachedToken(tokenName: any, ignoreExpiry?: boolean): any;
    _saveCachedToken(tokenName: any, token: any): void;
    _clearCachedToken(tokenName: any): void;
    _refreshSisuToken(sisuToken: any): Promise<any>;
    beginAuth(existingToken?: null, options?: {}): Promise<any>;
    _createSisuSession(deviceToken: any, options?: {}): Promise<any>;
    completeAuth(authorizationCode: any, options?: {}): Promise<{
        access_token: string;
        refresh_token: any;
        user_id: any;
        expires_in: any;
        token_type: any;
        scope: any;
        expiresOn: Date;
    }>;
    getXSTSToken(relyingParty?: string): Promise<{
        Token: any;
        uhs: any;
        xid: any;
        expiresOn: Date;
        DisplayClaims: any;
    }>;
    formatXSTS(xstsToken: any): string;
    authenticateUser(sisuToken: any, deviceToken?: null): Promise<{
        UserToken: {
            Token: any;
            UserHash: any;
            expiresOn: Date;
            DisplayClaims: any;
        };
        TitleToken: {
            Token: any;
            expiresOn: Date;
        };
        DeviceToken: null;
    }>;
}
