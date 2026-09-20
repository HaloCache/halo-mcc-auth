import fs from 'fs';
import path from 'path';
import { SisuAuth } from './sisu-auth.js';
import { resolveAuthOptions } from './utils.js';

function isAuthenticationFailure(error) {
    const status = error?.response?.status ?? error?.response?.statusCode;
    if (status === 401 || status === 403 || error?.code === 'AUTH_REQUIRED') return true;
    return /authentication required|expired|invalid token|missing .*token|\b40[13]\b/i.test(
        String(error?.message ?? ''),
    );
}

/**
 * Manages cached credentials, token refresh, and API tokens.
 *
 * @class XboxAuth
 */
export class XboxAuth {
    /** @private @type {{debug: Function, info: Function, warn: Function, error: Function}} */
    log;
    /** @private @type {SisuAuth} */
    sisuAuth;
    /** @type {string|null} */
    xuid;
    /** @type {string|null} */
    userHash;
    /** @type {string|null} */
    gamertag;
    /** @private @type {Promise<boolean>|null} */
    initMutex;
    /** @private @type {Promise<Object>|null} */
    playFabAuthMutex;
    /** @private @type {Object|null} */
    playFabTokenCache;
    /** @private @type {number|null} */
    playFabTokenExpiry;

    /**
     * @param {Object} options - Authentication options
     * @param {string} [options.cacheDir] - Directory path for caching tokens
     * @param {string} options.sessionName - Filename namespace for cached credentials; independent of account identity.
     * @param {Object} [options.logger] - Custom logger instance ({ debug, info, warn, error })
     */
    constructor(options) {
        const resolved = resolveAuthOptions(options, 'XboxAuth');
        this.cacheDir = resolved.cacheDir;
        this.sessionName = resolved.sessionName;

        this.log = resolved.logger;

        this.sisuAuth = new SisuAuth({
            cacheDir: this.cacheDir,
            sessionName: this.sessionName,
            logger: this.log
        });

        this.xuid = null;
        this.userHash = null;
        this.gamertag = null;
        this.authenticated = false;
        this.initMutex = null;
        this.playFabAuthMutex = null;
        this.playFabTokenCache = null;
        this.playFabTokenExpiry = null;

        fs.mkdirSync(this.cacheDir, { recursive: true, mode: 0o700 });
    }

    async initialize() {
        if (this.initMutex) {
            await this.initMutex;
            if (this.authenticated) return true;
        }

        this.initMutex = this._performInitialize();
        try {
            const result = await this.initMutex;
            return result;
        } finally {
            this.initMutex = null;
        }
    }

    async _performInitialize() {
        if (this.authenticated) {
            try {
                await this.sisuAuth.getXSTSToken('http://xboxlive.com');
                return true;
            } catch (error) {
                this.authenticated = false;
            }
        }

        const hasCachedTokens = this._checkCachedTokens();

        if (!hasCachedTokens) {
            const sisuPath = path.join(this.cacheDir, `${this.sessionName}_sisu_xbl.json`);
            if (fs.existsSync(sisuPath)) {
                this.log.debug('Cached tokens missing or expired, but refresh token found. Attempting refresh via SisuAuth.');
            } else {
                const error = new Error('Authentication required (no valid tokens)');
                error.code = 'AUTH_REQUIRED';
                throw error;
            }
        }

        try {
            const xstsToken = await this.sisuAuth.getXSTSToken('http://xboxlive.com');
            this.xuid = xstsToken.xid;
            this.userHash = xstsToken.uhs;
            this.gamertag = xstsToken.DisplayClaims?.xui?.[0]?.gtg || null;

            this.authenticated = true;
            return true;
        } catch (error) {
            this.authenticated = false;

            this.log.error(`[AuthDebug] XSTS Token Exchange Failed: ${error.message}`);
            if (error.response?.data) {
                this.log.error(`[AuthDebug] XSTS Error Response: ${JSON.stringify(error.response.data)}`);
            }

            if (error.message.includes('401') || error.message.includes('expired')) {
                const authError = new Error('Authentication required (tokens expired or invalid)');
                authError.code = 'AUTH_REQUIRED';
                authError.originalError = error;
                throw authError;
            }
            throw error;
        }
    }

    /**
     * Check if cached tokens exist and appear valid
     * @private
     * @returns {boolean} True if cached tokens exist
     */
    _checkCachedTokens() {
        try {
            const userTokenPath = path.join(this.cacheDir, `${this.sessionName}_user_token.json`);
            const titleTokenPath = path.join(this.cacheDir, `${this.sessionName}_title_token.json`);
            const deviceTokenPath = path.join(this.cacheDir, `${this.sessionName}_device_token.json`);

            this.log.info(`[AuthDebug] Checking tokens in: ${this.cacheDir}`);

            if (!fs.existsSync(userTokenPath)) {
                this.log.warn(`[AuthDebug] Missing User Token: ${userTokenPath}`);
                return false;
            }
            if (!fs.existsSync(titleTokenPath)) {
                this.log.warn(`[AuthDebug] Missing Title Token: ${titleTokenPath}`);
                return false;
            }
            if (!fs.existsSync(deviceTokenPath)) {
                this.log.warn(`[AuthDebug] Missing Device Token: ${deviceTokenPath}`);
                return false;
            }

            const tokenData = JSON.parse(fs.readFileSync(userTokenPath, 'utf8'));

            if (!tokenData || !tokenData.Token) {
                this.log.warn(' Cached user token file exists but is malformed (No Token field)');
                return false;
            }

            if (tokenData.expiresOn) {
                const expiryTime = new Date(tokenData.expiresOn).getTime();
                const now = Date.now();
                const bufferMs = 5 * 60 * 1000;

                if (!Number.isFinite(expiryTime) || expiryTime - bufferMs < now) {
                    this.log.info(` Cached tokens are expired. Expires: ${tokenData.expiresOn}, Now: ${new Date().toISOString()}`);
                    return false;
                }
            } else {
                this.log.warn(' Cached user token missing expiresOn field');
                return false;
            }

            this.log.debug(' Cached tokens valid and ready.');
            return true;
        } catch (error) {
            this.log.warn(' Error checking cached tokens:', error.message);
            return false;
        }
    }

    async ensureAuthenticated() {
        if (!this.authenticated) {
            await this.initialize();
        }
    }

    /**
     * Get XSTS token for a specific relying party
     *
     * @param {string} [relyingParty='http://xboxlive.com'] - Relying party URL
     * @returns {Promise<{userHash: string, token: string, tokenString: string, userXUID: string}>} Token details
     */
    async getXboxToken(relyingParty = 'http://xboxlive.com') {
        await this.ensureAuthenticated();
        try {
            const xstsToken = await this.sisuAuth.getXSTSToken(relyingParty);

            if (xstsToken.uhs) this.userHash = xstsToken.uhs;
            if (xstsToken.xid) this.xuid = xstsToken.xid;

            const tokenString = this.sisuAuth.formatXSTS(xstsToken);

            return {
                userHash: xstsToken.uhs,
                token: xstsToken.Token,
                tokenString,
                userXUID: xstsToken.xid
            };
        } catch (error) {
            if (!isAuthenticationFailure(error)) throw error;
            this.authenticated = false;
            await this.initialize();
            const xstsToken = await this.sisuAuth.getXSTSToken(relyingParty);
            const tokenString = this.sisuAuth.formatXSTS(xstsToken);
            return {
                userHash: xstsToken.uhs,
                token: xstsToken.Token,
                tokenString,
                userXUID: xstsToken.xid
            };
        }
    }

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
    async getPlayFabToken() {
        if (this.playFabAuthMutex) {
            await this.playFabAuthMutex;
            if (this.playFabTokenCache && this.playFabTokenExpiry && Date.now() < this.playFabTokenExpiry) {
                return this.playFabTokenCache;
            }
        }

        if (this.playFabTokenCache && this.playFabTokenExpiry && Date.now() < this.playFabTokenExpiry) {
            return this.playFabTokenCache;
        }

        this.playFabAuthMutex = (async () => {
            await this.ensureAuthenticated();
            return this._performPlayFabAuth();
        })();
        try {
            return await this.playFabAuthMutex;
        } finally {
            this.playFabAuthMutex = null;
        }
    }

    async _performPlayFabAuth() {
        const xboxToken = await this.getXboxToken('rp://playfabapi.com/');
        const xboxTokenValue = xboxToken.tokenString;

        const requestData = {
            TitleId: 'EE38',
            XboxToken: xboxTokenValue,
            CreateAccount: true
        };

        const requestHeaders = {
            'Content-Type': 'application/json'
        };

        try {
            const response = await this.sisuAuth.client.post(
                'https://ee38.playfabapi.com/Client/LoginWithXbox',
                {
                    json: requestData,
                    headers: requestHeaders,
                    responseType: 'json',
                    retry: { limit: 0 },
                }
            );

            const responseBody = response.body;

            if (response.statusCode !== 200 || responseBody?.code !== 200) {
                throw new Error(`PlayFab login failed: ${response.statusCode} ${JSON.stringify(responseBody)}`);
            }

            const result = {
                SessionTicket: responseBody.data.SessionTicket,
                EntityToken: responseBody.data.EntityToken,
                PlayFabId: responseBody.data.PlayFabId,
                NewlyCreated: responseBody.data.NewlyCreated
            };

            this.playFabTokenCache = result;
            this.playFabTokenExpiry = Date.now() + (5 * 60 * 1000);
            return result;
        } catch (error) {
            this.playFabTokenCache = null;
            throw error;
        }
    }

    async beginInteractiveAuth() {
        return this.sisuAuth.beginAuth();
    }

    async completeInteractiveAuth(authorizationCode) {
        const sisuXblToken = await this.sisuAuth.completeAuth(authorizationCode);

        this.sisuAuth._saveCachedToken('sisu_xbl', sisuXblToken);

        await this.sisuAuth.authenticateUser(sisuXblToken);
        return true;
    }

    /**
     * Get current authentication status
     * @returns {Object} Status object with xuid, gamertag, and auth state
     */
    getStatus() {
        return {
            authenticated: this.authenticated,
            sessionName: this.sessionName,
            gamertag: this.gamertag,
            xuid: this.xuid,
            userHash: this.userHash
        };
    }
}
