export declare const silentLogger: Readonly<{
    debug(): void;
    info(): void;
    warn(): void;
    error(): void;
}>;
export declare function normalizeLogger(logger: any): Readonly<{
    debug(): void;
    info(): void;
    warn(): void;
    error(): void;
}> | {
    [k: string]: any;
};
/**
 * Validate the filename namespace used for cached credentials.
 *
 * @param {unknown} value
 * @param {string} owner - Class or caller name used in validation errors
 * @returns {string}
 */
export declare function validateSessionName(value: unknown, owner?: string): string;
/**
 * Resolve the shared constructor options used by both authentication clients.
 *
 * @param {Object} [options]
 * @param {string} owner
 * @returns {{cacheDir: string, sessionName: string, logger: Object}}
 */
export declare function resolveAuthOptions(options?: Object, owner?: string): {
    cacheDir: string;
    sessionName: string;
    logger: Object;
};
/**
 * Persist credential JSON with owner-only permissions where the platform supports them.
 *
 * @param {string} filePath
 * @param {unknown} value
 */
export declare function writePrivateJsonFile(filePath: string, value: unknown): void;
/**
 * Get the platform-specific application data directory
 * @param {string} appName - The name of the application (e.g. 'haloscanner')
 * @returns {string} Absolute path to the app data directory
 */
export declare function getAppDataPath(appName?: string): string;
