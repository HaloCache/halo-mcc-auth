/**
 * SISU authentication using the Halo MCC client ID and Win32 device type.
 * Refresh tokens use the `t=` prefix; new tokens use `d=`.
 *
 * Based on work and documentation done by Gamergotten
 *
 * @module sisu-auth
 */

import fs from 'fs';
import path from 'path';
import crypto from 'node:crypto';
import { resolveAuthOptions, writePrivateJsonFile } from './utils.js';
import { createAuthHttpClient } from './http-client.js';

const HALO_MCC_CLIENT_ID = '000000004825fc1f';
const HALO_MCC_TITLE_ID = '1144039928';

const SCOPES = ['xboxlive.signin', 'offline_access'];
const EXPIRING_TOKEN_NAMES = new Set(['user_token', 'title_token', 'device_token']);

export class SisuAuth {
    /**
     * @param {Object} options - Configuration options
     * @param {string} [options.cacheDir] - Directory to store auth tokens
     * @param {string} options.sessionName - Filename namespace for cached credentials; independent of account identity.
     * @param {Object} [options.logger] - Custom logger instance
     */
    constructor(options = {}) {
        const resolved = resolveAuthOptions(options, 'SisuAuth');
        this.cacheDir = resolved.cacheDir;
        this.sessionName = resolved.sessionName;

        this.log = resolved.logger;

        this.xboxKeypair = null;
        this.xboxJwk = null;

        this.sisuSessionId = null;
        this.pkceCodeVerifier = null;
        this.pkceCodeChallenge = null;
        this.pkceState = null;
        this.msCv = null;
        this.refreshPromise = null;

        const proxyUrl = process.env.AUTH_PROXY_URL;
        if (proxyUrl) {
            this.log.info('[AuthInfo] Authentication proxy is enabled');
        }

        this.client = createAuthHttpClient({
            responseType: 'json',
            proxyUrl,
            retry: {
                limit: 3,
                methods: ['POST', 'GET'],
                statusCodes: [408, 413, 429, 500, 502, 503, 504]
            }
        });

        fs.mkdirSync(this.cacheDir, { recursive: true, mode: 0o700 });

        const cachedSession = this._loadCachedToken('sisu_session');
        if (cachedSession?.sessionId) {
            this.sisuSessionId = cachedSession.sessionId;
            this.log.debug('Restored sessionId from cache on initialization');
        }

        const cachedDeviceId = this._loadCachedToken('device_id');
        if (cachedDeviceId?.id) {
            this.deviceId = cachedDeviceId.id;
            this.log.debug('Restored persistent Device ID from cache', { deviceId: this.deviceId });
        } else {
            this.deviceId = crypto.randomUUID();
            this._saveCachedToken('device_id', { id: this.deviceId });
            this.log.debug('Generated new persistent Device ID', { deviceId: this.deviceId });
        }
    }

    /**
     * Initialize crypto keypair for device authentication
     * @private
     */
    async _initCrypto() {
        if (this.xboxKeypair) return;

        const cachedKey = this._loadCachedToken('device_key', true);
        if (cachedKey && cachedKey.private && cachedKey.public) {
            try {
                const privateKey = await crypto.subtle.importKey(
                    'jwk',
                    cachedKey.private,
                    { name: 'ECDSA', namedCurve: 'P-256' },
                    true,
                    ['sign']
                );
                const publicKey = await crypto.subtle.importKey(
                    'jwk',
                    cachedKey.public,
                    { name: 'ECDSA', namedCurve: 'P-256' },
                    true,
                    ['verify']
                );

                this.xboxKeypair = { privateKey, publicKey };
                this.xboxJwk = cachedKey.public;
                this.log.debug('Restored persistent crypto keypair');
                return;
            } catch (error) {
                this.log.warn('Failed to import cached keypair, generating new one', error);
            }
        }

        this.log.debug('Initializing crypto keypair for device authentication');

        this.xboxKeypair = await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            true,
            ['sign', 'verify']
        );

        const publicKeyJwk = await crypto.subtle.exportKey('jwk', this.xboxKeypair.publicKey);
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', this.xboxKeypair.privateKey);

        this.xboxJwk = {
            kty: publicKeyJwk.kty,
            x: publicKeyJwk.x,
            y: publicKeyJwk.y,
            crv: publicKeyJwk.crv,
            alg: 'ES256',
            use: 'sig'
        };

        this._saveCachedToken('device_key', {
            private: privateKeyJwk,
            public: this.xboxJwk
        });

        this.log.debug('Crypto keypair initialized and persisted');
    }

    /**
     * Generate MS-CV (Microsoft Correlation Vector) header value
     * @private
     */
    _generateMsCv() {
        const base = Array.from({ length: 16 }, () =>
            Math.floor(Math.random() * 16).toString(16)
        ).join('');
        const version = Math.floor(Math.random() * 100) + 1;
        return `${base}.${version}`;
    }

    /**
     * Generate PKCE code verifier and challenge
     * @private
     */
    async _generatePKCE() {
        const state = crypto.randomBytes(64);
        this.pkceState = state.toString('base64url');

        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        const array = crypto.randomBytes(64);
        this.pkceCodeVerifier = Array.from(array, byte => charset[byte % charset.length]).join('');

        const hash = crypto.createHash('sha256').update(this.pkceCodeVerifier).digest();
        this.pkceCodeChallenge = hash.toString('base64url');

        this.log.debug('PKCE codes generated');
    }

    /**
     * Sign an Xbox Live request over its path, query, and UTF-8 payload bytes.
     *
     * @private
     */
    async _sign(url, authorizationToken, payload, method = 'POST') {
        const windowsTimestamp = (BigInt((Date.now() / 1000) | 0) + 11644473600n) * 10000000n;

        const parsedUrl = new URL(url);
        const pathAndQuery = parsedUrl.pathname + parsedUrl.search;

        const byteLen = (s) => Buffer.byteLength(String(s), 'utf8');
        const allocSize = 5 + 9 + byteLen(method) + 1 + byteLen(pathAndQuery) + 1 +
            byteLen(authorizationToken) + 1 + byteLen(payload) + 1;

        const buffer = Buffer.alloc(allocSize);
        let offset = 0;

        buffer.writeInt32BE(1, offset); offset += 4;
        buffer.writeUInt8(0, offset); offset += 1;

        const high = Number(windowsTimestamp >> 32n);
        const low = Number(windowsTimestamp & 0xFFFFFFFFn);
        buffer.writeUInt32BE(high, offset); offset += 4;
        buffer.writeUInt32BE(low, offset); offset += 4;
        buffer.writeUInt8(0, offset); offset += 1;

        const writeStringNT = (str) => {
            const bytes = Buffer.from(str, 'utf8');
            bytes.copy(buffer, offset);
            offset += bytes.length;
            buffer.writeUInt8(0, offset);
            offset += 1;
        };

        writeStringNT(method);
        writeStringNT(pathAndQuery);
        writeStringNT(authorizationToken);
        writeStringNT(payload);

        const data = new Uint8Array(buffer);
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            this.xboxKeypair.privateKey,
            data
        );

        const totalSize = signature.byteLength + 12;
        const headerBuffer = Buffer.alloc(totalSize);
        let headerOffset = 0;

        headerBuffer.writeInt32BE(1, headerOffset); headerOffset += 4;
        headerBuffer.writeUInt32BE(high, headerOffset); headerOffset += 4;
        headerBuffer.writeUInt32BE(low, headerOffset); headerOffset += 4;

        Buffer.from(signature).copy(headerBuffer, headerOffset);

        return headerBuffer.toString('base64');
    }

    /**
     * Normalize transport errors to the package's response-error contract.
     * @private
     */
    _normalizeError(error) {
        if (error.response) {
            error.response.data = error.response.body;
            error.response.status = error.response.statusCode;
        }
        return error;
    }

    /**
     * Get device token (Win32 device type)
     * @private
     */
    async _getDeviceToken(retryCount = 0) {
        await this._initCrypto();

        const payload = {
            RelyingParty: 'http://auth.xboxlive.com',
            TokenType: 'JWT',
            Properties: {
                AuthMethod: 'ProofOfPossession',
                Id: `{${this.deviceId}}`,
                DeviceType: 'Win32',
                Version: '10.0.19045',
                ProofKey: this.xboxJwk
            }
        };

        const body = JSON.stringify(payload);
        const signature = await this._sign('https://device.auth.xboxlive.com/device/authenticate', '', body);

        const headers = {
            'Cache-Control': 'no-store, must-revalidate, no-cache',
            'x-xbl-contract-version': '1',
            'Signature': signature,
            'Content-Type': 'application/json'
        };

        try {
            this.log.info('[AuthTrace] Requesting device token', {
                url: 'https://device.auth.xboxlive.com/device/authenticate',
                DeviceId: this.deviceId
            });

            const response = await this.client.post(
                'https://device.auth.xboxlive.com/device/authenticate',
                {
                    body: body,
                    headers: headers
                }
            );

            const responseData = response.body;

            this.log.debug('Device token obtained successfully');
            return {
                Token: responseData.Token,
                expiresOn: new Date(responseData.NotAfter)
            };
        } catch (error) {
            this._normalizeError(error);

            if (error.response && error.response.status === 403 && retryCount === 0) {
                this.log.warn('Device authentication rejected (403). Rotating Device ID/Key and retrying...');

                this.xboxKeypair = null;
                this.xboxJwk = null;
                this._clearCachedToken('device_key');
                this._clearCachedToken('device_token');

                this.deviceId = crypto.randomUUID();

                this._saveCachedToken('device_id', { id: this.deviceId });
                return this._getDeviceToken(1);
            }

            this.log.error('Device authentication error', { error: error.message });
            throw error;
        }
    }

    /**
     * Get XSTS token for a relying party
     * @private
     */
    async _getXSTSToken(userToken, deviceToken, titleToken, relyingParty = 'http://xboxlive.com') {
        const payload = {
            RelyingParty: relyingParty,
            TokenType: 'JWT',
            Properties: {
                UserTokens: [userToken.Token],
                DeviceToken: deviceToken.Token,
                TitleToken: titleToken.Token,
                SandboxId: 'RETAIL'
            }
        };

        const headers = {
            'Cache-Control': 'no-store, must-revalidate, no-cache',
            'x-xbl-contract-version': '1',
            'Content-Type': 'application/json'
        };

        try {
            const response = await this.client.post(
                'https://xsts.auth.xboxlive.com/xsts/authorize',
                {
                    json: payload,
                    headers: headers
                }
            );

            const responseData = response.body;

            const xui = responseData.DisplayClaims?.xui?.[0];
            if (!xui) {
                throw new Error('Invalid XSTS response: missing DisplayClaims.xui');
            }

            return {
                Token: responseData.Token,
                uhs: xui.uhs,
                xid: xui.xid || null,
                expiresOn: new Date(responseData.NotAfter),
                DisplayClaims: responseData.DisplayClaims
            };
        } catch (error) {
            this._normalizeError(error);
            if (error.response && error.response.data && error.response.data.XErr) {
                this._checkTokenError(error.response.data.XErr, error.response.data);
            }
            throw error;
        }
    }

    _checkTokenError(errorCode, response) {
        const errors = {
            2148916227: 'Your account was banned by Xbox or the service is down (0x8015DC03).',
            2148916229: 'Your account is restricted (0x8015DC05).',
            2148916233: 'Your account does not have an Xbox profile (0x8015DC09).',
            2148916234: 'Your account has not accepted Xbox\'s Terms of Service (0x8015DC0A).',
            2148916235: 'Region not authorized (0x8015DC0B).',
            2148916236: 'Proof of age required (0x8015DC0C).',
            2148916237: 'Playtime limit reached (0x8015DC0D).',
            2148916238: 'Account under 18 years old (0x8015DC0E).',
            2148916254: 'The title is not authenticated (0x8015DC1E).'
        };

        const message = errors[errorCode] || `Xbox Live authentication failed. XErr: ${errorCode}`;
        const detail = response ? JSON.stringify(response) : 'No Response Data';
        throw new Error(`${message}\n${detail}`);
    }

    _loadCachedToken(tokenName, ignoreExpiry = false) {
        const filePath = path.join(this.cacheDir, `${this.sessionName}_${tokenName}.json`);

        if (!fs.existsSync(filePath)) {
            return null;
        }

        try {
            const data = fs.readFileSync(filePath, 'utf8');
            const token = JSON.parse(data);

            if (!ignoreExpiry && EXPIRING_TOKEN_NAMES.has(tokenName)) {
                const expiryTime = Date.parse(token.expiresOn);
                if (!Number.isFinite(expiryTime)) {
                    this.log.warn(`[AuthDebug] [${this.sessionName}] Token has no valid expiry: ${tokenName}`);
                    return null;
                }
                const remainingMs = expiryTime - Date.now();
                const bufferMs = 5 * 60 * 1000;
                if (remainingMs <= bufferMs) {
                    this.log.warn(`[AuthDebug] [${this.sessionName}] Token expired or expiring soon: ${filePath} (expires: ${token.expiresOn}, Now: ${new Date().toISOString()}, Remaining: ${remainingMs}ms)`);
                    return null;
                }
            }
            return token;
        } catch (error) {
            this.log.error(`[AuthDebug] [${this.sessionName}] Failed to load token ${tokenName}: ${error.message}`);
            return null;
        }
    }

    _saveCachedToken(tokenName, token) {
        const filePath = path.join(this.cacheDir, `${this.sessionName}_${tokenName}.json`);
        try {
            writePrivateJsonFile(filePath, token);
        } catch (error) {
            this.log.error(`Failed to save cached token ${tokenName}`, { error: error.message });
            throw error;
        }
    }

    _clearCachedToken(tokenName) {
        const filePath = path.join(this.cacheDir, `${this.sessionName}_${tokenName}.json`);
        if (fs.existsSync(filePath)) {
            try {
                fs.unlinkSync(filePath);
            } catch (error) {
                this.log.warn(`Failed to clear cached token ${tokenName}`, { error: error.message });
            }
        }
    }

    async _refreshSisuToken(sisuToken) {
        if (!sisuToken?.refresh_token) {
            throw new Error('No refresh token available');
        }

        this.log.info(`[AuthDebug] [${this.sessionName}] Refreshing SISU token`);

        const params = new URLSearchParams({
            scope: SCOPES.join(' '),
            client_id: HALO_MCC_CLIENT_ID,
            grant_type: 'refresh_token',
            refresh_token: sisuToken.refresh_token
        });

        try {
            const response = await this.client.post(
                'https://login.live.com/oauth20_token.srf',
                {
                    body: params.toString(),
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }
            );

            const newToken = response.body;

            if (newToken.error || !newToken.access_token) {
                const errorDesc = newToken.error_description || newToken.error || 'Missing access_token in response';
                throw new Error(errorDesc);
            }

            if (!newToken.refresh_token) {
                newToken.refresh_token = sisuToken.refresh_token;
            }

            newToken.access_token = 'd=' + newToken.access_token;
            newToken.expiresOn = new Date(Date.now() + (newToken.expires_in * 1000));

            return newToken;
        } catch (error) {
            this._normalizeError(error);
            const errDetail = error.response?.data ? JSON.stringify(error.response.data) : error.message;
            this.log.error(`[AuthDebug] [${this.sessionName}] Token refresh failed response: ${errDetail}`);
            throw new Error(`Token refresh failed: ${error.response?.status || 'NetErr'} ${errDetail}`);
        }
    }

    async beginAuth(existingToken = null, options = {}) {
        if (existingToken) {
            try {
                return await this._refreshSisuToken(existingToken);
            } catch (error) {
                this.log.warn('Failed to refresh existing token, starting new auth flow');
            }
        }

        this.log.info('Starting fresh interactive auth flow - clearing stale tokens');
        this._clearCachedToken('sisu_xbl');
        this._clearCachedToken('user_token');
        this._clearCachedToken('title_token');
        this._clearCachedToken('device_token');
        this._clearCachedToken('sisu_session');

        this.sisuSessionId = null;

        await this._initCrypto();
        await this._generatePKCE();
        this.msCv = this._generateMsCv();

        if (!this.deviceId) {
            const cachedDeviceId = this._loadCachedToken('device_id');
            if (cachedDeviceId?.id) this.deviceId = cachedDeviceId.id;
            else {
                this.deviceId = crypto.randomUUID();
                this._saveCachedToken('device_id', { id: this.deviceId });
            }
        }

        let deviceToken;
        try {
            deviceToken = await this._getDeviceToken();
            this._saveCachedToken('device_token', deviceToken);
        } catch (error) {
            throw error;
        }

        const responseData = await this._createSisuSession(deviceToken, options);

        let authUrl = responseData.MsaOauthRedirect;
        if (!authUrl) {
            throw new Error('Missing MsaOauthRedirect in response');
        }

        return {
            authUrl,
            sessionId: this.sisuSessionId,
            state: this.pkceState,
            pkceCodeVerifier: this.pkceCodeVerifier
        };
    }
    async _createSisuSession(deviceToken, options = {}) {
        this.log.info('[AuthTrace] [Headless] Initiating background SISU session registration...');
        const redirectUri = options.redirectUri || 'https://login.live.com/oauth20_desktop.srf';
        const clientId = options.clientId || HALO_MCC_CLIENT_ID;

        const payload = {
            AppId: clientId,
            TitleId: HALO_MCC_TITLE_ID,
            RedirectUri: redirectUri,
            DeviceToken: deviceToken.Token,
            Sandbox: 'RETAIL',
            TokenType: 'code',
            Offers: ['xboxlive.signin', 'offline_access'],
            Query: {
                code_challenge: this.pkceCodeChallenge,
                code_challenge_method: 'S256',
                state: this.pkceState
            }
        };

        const body = JSON.stringify(payload);
        const signature = await this._sign('https://sisu.xboxlive.com/authenticate', '', body);

        const headers = {
            'Connection': 'Keep-Alive',
            'Content-Type': 'application/json; charset=utf-8',
            'MS-CV': `${this.msCv}.5.0`,
            'signature': signature,
            'x-xbl-contract-version': '1'
        };

        try {
            const response = await this.client.post(
                'https://sisu.xboxlive.com/authenticate',
                {
                    body: body,
                    headers: headers
                }
            );

            this.sisuSessionId = response.headers['x-sessionid'] || response.headers['X-SessionId'];
            if (!this.sisuSessionId) {
                this.log.error('[AuthTrace] [Headless] Missing X-SessionId in /authenticate response headers');
                throw new Error('SISU begin auth failed: missing X-SessionId header');
            }

            this.log.info(`[AuthTrace] [Headless] Successfully registered fresh backend Session ID: ${this.sisuSessionId}`);
            this._saveCachedToken('sisu_session', { sessionId: this.sisuSessionId });

            return response.body;
        } catch (error) {
            this.log.error(`[AuthTrace] [Headless] /authenticate invocation failed. Status: ${error.response?.status}. Body: ${error.response?.body}`);
            throw error;
        }
    }

    async completeAuth(authorizationCode, options = {}) {
        this.log.debug('completeAuth called');

        if (authorizationCode.includes('code=')) {
            const match = authorizationCode.match(/code=([^&]+)/);
            if (match && match[1]) {
                authorizationCode = decodeURIComponent(match[1]);
                this.log.debug('Extracted code from URL');
            }
        }

        this.log.debug(`Final authorization code: ${authorizationCode.substring(0, 5)}...`);

        const verifier = options.pkceCodeVerifier || this.pkceCodeVerifier;
        if (!verifier) {
            throw new Error('PKCE Code Verifier missing. Pass it in options for stateless flow or ensure instance state.');
        }

        const redirectUri = options.redirectUri || 'https://login.live.com/oauth20_desktop.srf';

        const params = new URLSearchParams({
            client_id: HALO_MCC_CLIENT_ID,
            code: authorizationCode,
            code_verifier: verifier,
            grant_type: 'authorization_code',
            redirect_uri: redirectUri,
            scope: SCOPES.join(' ')
        });

        this.log.debug('Exchanging code at https://login.live.com/oauth20_token.srf');

        try {
            const response = await this.client.post(
                'https://login.live.com/oauth20_token.srf',
                {
                    body: params.toString(),
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }
            );

            const tokenData = response.body;
            this.log.debug('Token exchange successful');

            const accessToken = tokenData.access_token;
            const refreshToken = tokenData.refresh_token;

            if (!accessToken) {
                throw new Error('No access_token in response');
            }

            const sisuToken = {
                access_token: 'd=' + accessToken,
                refresh_token: refreshToken,
                user_id: tokenData.user_id,
                expires_in: tokenData.expires_in,
                token_type: tokenData.token_type,
                scope: tokenData.scope,
                expiresOn: new Date(Date.now() + (tokenData.expires_in * 1000))
            };

            this._saveCachedToken('sisu_xbl', sisuToken);
            return sisuToken;

        } catch (error) {
            this._normalizeError(error);
            this.log.error('Token exchange failed:', error.response?.data);
            throw new Error(`Token exchange failed: ${error.response?.status} ${JSON.stringify(error.response?.data)}`);
        }
    }

    async getXSTSToken(relyingParty = 'http://xboxlive.com') {
        if (this.refreshPromise) {
            try {
                await this.refreshPromise;
            } catch {
            }
        }

        let userToken = this._loadCachedToken('user_token');
        let titleToken = this._loadCachedToken('title_token');
        let deviceToken = this._loadCachedToken('device_token');

        if (!userToken || !titleToken || !deviceToken) {
            const sisuXbl = this._loadCachedToken('sisu_xbl', true);
            if (sisuXbl && sisuXbl.refresh_token) {
                this.log.info('[SisuAuth] Tokens missing/expired - attempting transparent refresh via SISU');

                this.refreshPromise = (async () => {
                    const newSisu = await this._refreshSisuToken(sisuXbl);
                    this._saveCachedToken('sisu_xbl', newSisu);

                    let device = deviceToken;
                    if (!device) {
                        try {
                            device = await this._getDeviceToken();
                            this._saveCachedToken('device_token', device);
                        } catch (e) {
                            this.log.warn('Failed to regenerate device token', e);
                            throw e;
                        }
                    }

                    this.log.info('[SisuAuth] Creating a distinct backend SISU session for refresh');
                    await this._initCrypto();
                    await this._generatePKCE();
                    this.msCv = this._generateMsCv();
                    await this._createSisuSession(device);
                    await this.authenticateUser(newSisu, device);

                    return device;
                })();

                try {
                    deviceToken = await this.refreshPromise;
                    userToken = this._loadCachedToken('user_token');
                    titleToken = this._loadCachedToken('title_token');
                } catch (error) {
                    this.log.error('[SisuAuth] Transparent refresh failed:', error.message);
                    throw error;
                } finally {
                    this.refreshPromise = null;
                }
            }
        }

        if (!userToken || !titleToken || !deviceToken) {
            throw new Error('Authentication required: Missing or expired User/Title/Device tokens.');
        }

        return this._getXSTSToken(userToken, deviceToken, titleToken, relyingParty);
    }

    formatXSTS(xstsToken) {
        if (!xstsToken || !xstsToken.Token || !xstsToken.uhs) {
            throw new Error('Invalid XSTS token structure for formatting');
        }
        return `XBL3.0 x=${xstsToken.uhs};${xstsToken.Token}`;
    }

    async authenticateUser(sisuToken, deviceToken = null) {
        await this._initCrypto();

        if (!this.sisuSessionId) {
            const cachedSession = this._loadCachedToken('sisu_session');
            if (cachedSession && cachedSession.sessionId) {
                this.sisuSessionId = cachedSession.sessionId;
            } else {
                this.log.error('CRITICAL: Session ID missing for SISU Authorize');
            }
        }

        if (!deviceToken) {
            this._clearCachedToken('device_token');
            deviceToken = await this._getDeviceToken();
            this._saveCachedToken('device_token', deviceToken);
        }

        this.log.debug('Authenticating User against SISU (Reverted Logic)...');

        const activeSessionId = this.sisuSessionId || crypto.randomUUID();

        const payload = {
            AccessToken: sisuToken.access_token,
            AppId: HALO_MCC_CLIENT_ID,
            DeviceToken: deviceToken.Token,
            Sandbox: 'RETAIL',
            UseModernGamertag: true,
            SiteName: 'user.auth.xboxlive.com',
            RelyingParty: 'http://xboxlive.com',
            SessionId: activeSessionId,
            ProofKey: this.xboxJwk
        };

        const body = JSON.stringify(payload);

        const signature = await this._sign('https://sisu.xboxlive.com/authorize', '', body);

        const msCv = `${this.msCv || 'start'}.1`;

        const headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'MS-CV': msCv,
            'Signature': signature,
            'x-xbl-contract-version': '1',
            'User-Agent': 'axios/1.6.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, compress, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9'
        };

        try {
            const response = await this.client.post(
                'https://sisu.xboxlive.com/authorize',
                {
                    body: body,
                    headers: headers
                }
            );

            const data = response.body;
            this.log.debug('SISU User Authentication Successful');

            const xui = data.UserToken?.DisplayClaims?.xui?.[0];
            if (!xui) {
                this.log.error('SISU Auth Response Missing XUI', {
                    status: response.statusCode,
                    headers: response.headers,
                    body: data
                });
                throw new Error(`Missing DisplayClaims via SISU. Status: ${response.statusCode}. Body: '${JSON.stringify(data)}'`);
            }

            const userToken = {
                Token: data.UserToken.Token,
                UserHash: xui.uhs,
                expiresOn: new Date(data.UserToken.NotAfter),
                DisplayClaims: data.UserToken.DisplayClaims
            };

            const titleToken = {
                Token: data.TitleToken.Token,
                expiresOn: new Date(data.TitleToken.NotAfter)
            };

            this._saveCachedToken('user_token', userToken);
            this._saveCachedToken('title_token', titleToken);

            return {
                UserToken: userToken,
                TitleToken: titleToken,
                DeviceToken: deviceToken
            };

        } catch (error) {
            this._normalizeError(error);
            const errDetail = error.response?.body ? JSON.stringify(error.response.body) : (error.message || 'Unknown Error');

            if (error.response && error.response.statusCode === 403) {
                this.log.error('SISU 403 FORBIDDEN - Akamai Block Triggered');
            }

            this.log.error(`SISU authorize failed: ${errDetail}`);
            throw new Error(`SISU authorize failed: ${error.response?.statusCode || 'No Status'} - ${errDetail}`);
        }
    }
}
