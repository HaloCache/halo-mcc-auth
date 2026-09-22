/**
 * Manages cached credentials, token refresh, and API tokens.
 *
 * @class XboxAuth
 */
export declare class XboxAuth {
    cacheDir: string;
    sessionName: string;
    authenticated: boolean;
    /** @private @type {{debug: Function, info: Function, warn: Function, error: Function}} */
    private log;
    /** @private @type {SisuAuth} */
    private sisuAuth;
    /** @type {string|null} */
    xuid: string | null;
    /** @type {string|null} */
    userHash: string | null;
    /** @type {string|null} */
    gamertag: string | null;
    /** @private @type {Promise<boolean>|null} */
    private initMutex;
    /** @private @type {Promise<Object>|null} */
    private playFabAuthMutex;
    /** @private @type {Object|null} */
    private playFabTokenCache;
    /** @private @type {number|null} */
    private playFabTokenExpiry;
    /**
     * @param {Object} options - Authentication options
     * @param {string} [options.cacheDir] - Directory path for caching tokens
     * @param {string} options.sessionName - Filename namespace for cached credentials; independent of account identity.
     * @param {Object} [options.logger] - Custom logger instance ({ debug, info, warn, error })
     */
    constructor(options: {
        cacheDir?: string;
        sessionName: string;
        logger?: Object;
    });
    initialize(): Promise<boolean>;
    _performInitialize(): Promise<boolean>;
    /**
     * Check if cached tokens exist and appear valid
     * @private
     * @returns {boolean} True if cached tokens exist
     */
    private _checkCachedTokens;
    ensureAuthenticated(): Promise<void>;
    /**
     * Get XSTS token for a specific relying party
     *
     * @param {string} [relyingParty='http://xboxlive.com'] - Relying party URL
     * @returns {Promise<{userHash: string, token: string, tokenString: string, userXUID: string}>} Token details
     */
    getXboxToken(relyingParty?: string): Promise<{
        userHash: string;
        token: string;
        tokenString: string;
        userXUID: string;
    }>;
    /**
     * Get PlayFab token using Xbox Live authentication
     *
     * @returns {Promise<{
     *   SessionTicket: string,
     *   PlayFabId: string,
     *   EntityToken: {
     *     EntityToken: string,
     *     TokenExpiration: string,
     *     EntityKey: {
     *       Id: string,
     *       Type: string
     *     }
     *   },
     *   NewlyCreated: boolean
     * }>} PlayFab login result object
     */
    getPlayFabToken(): Promise<{
        SessionTicket: string;
        PlayFabId: string;
        EntityToken: {
            EntityToken: string;
            TokenExpiration: string;
            EntityKey: {
                Id: string;
                Type: string;
            };
        };
        NewlyCreated: boolean;
    }>;
    _performPlayFabAuth(): Promise<{
        SessionTicket: any;
        EntityToken: any;
        PlayFabId: any;
        NewlyCreated: any;
    }>;
    beginInteractiveAuth(): Promise<any>;
    completeInteractiveAuth(authorizationCode: any): Promise<boolean>;
    /**
     * Get current authentication status
     * @returns {Object} Status object with xuid, gamertag, and auth state
     */
    getStatus(): Object;
}
