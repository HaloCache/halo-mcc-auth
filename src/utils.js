import path from 'path';
import os from 'os';
import fs from 'fs';
import { randomUUID } from 'node:crypto';

export const silentLogger = Object.freeze({
    debug() {},
    info() {},
    warn() {},
    error() {},
});

export function normalizeLogger(logger) {
    if (!logger) return silentLogger;
    return Object.fromEntries(
        Object.keys(silentLogger).map(level => [
            level,
            typeof logger[level] === 'function' ? logger[level].bind(logger) : silentLogger[level],
        ]),
    );
}

const SESSION_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$/;

/**
 * Validate the filename namespace used for cached credentials.
 *
 * @param {unknown} value
 * @param {string} owner - Class or caller name used in validation errors
 * @returns {string}
 */
export function validateSessionName(value, owner = 'Authentication') {
    if (typeof value !== 'string' || !SESSION_NAME_PATTERN.test(value)) {
        throw new TypeError(
            `${owner}: sessionName must be 1-128 characters using letters, numbers, dot, underscore, @, +, or hyphen.`,
        );
    }
    return value;
}

/**
 * Resolve the shared constructor options used by both authentication clients.
 *
 * @param {Object} [options]
 * @param {string} owner
 * @returns {{cacheDir: string, sessionName: string, logger: Object}}
 */
export function resolveAuthOptions(options = {}, owner = 'Authentication') {
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
        throw new TypeError(`${owner}: options must be an object.`);
    }

    const suppliedName = options.sessionName;
    if (suppliedName === undefined || suppliedName === null || suppliedName === '') {
        throw new Error(`${owner}: a "sessionName" option is required.`);
    }

    let cacheDir;
    if (options.cacheDir !== undefined) {
        if (typeof options.cacheDir !== 'string' || options.cacheDir.trim() === '') {
            throw new TypeError(`${owner}: cacheDir must be a non-empty path string.`);
        }
        cacheDir = path.isAbsolute(options.cacheDir)
            ? options.cacheDir
            : path.resolve(process.cwd(), options.cacheDir);
    } else cacheDir = path.join(getAppDataPath('haloscanner'), 'auth');

    return {
        cacheDir,
        sessionName: validateSessionName(suppliedName, owner),
        logger: normalizeLogger(options.logger),
    };
}

/**
 * Persist credential JSON with owner-only permissions where the platform supports them.
 *
 * @param {string} filePath
 * @param {unknown} value
 */
export function writePrivateJsonFile(filePath, value) {
    const temporaryPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
    try {
        fs.writeFileSync(temporaryPath, JSON.stringify(value, null, 2), {
            encoding: 'utf8',
            mode: 0o600,
            flag: 'wx',
            flush: true,
        });
        fs.chmodSync(temporaryPath, 0o600);
        fs.renameSync(temporaryPath, filePath);
    } catch (error) {
        try {
            fs.unlinkSync(temporaryPath);
        } catch (cleanupError) {
            if (cleanupError.code !== 'ENOENT') error.cleanupError = cleanupError;
        }
        throw error;
    }
}

/**
 * Get the platform-specific application data directory
 * @param {string} appName - The name of the application (e.g. 'haloscanner')
 * @returns {string} Absolute path to the app data directory
 */
export function getAppDataPath(appName = 'haloscanner') {
    if (typeof appName !== 'string' || !SESSION_NAME_PATTERN.test(appName)) {
        throw new TypeError(
            'getAppDataPath: appName must be a single filename-safe path segment.',
        );
    }
    const homedir = os.homedir();

    if (process.platform === 'win32') {
        return path.join(process.env.APPDATA || path.join(homedir, 'AppData', 'Roaming'), appName);
    } else if (process.platform === 'darwin') {
        return path.join(homedir, 'Library', 'Application Support', appName);
    } else {
        return path.join(process.env.XDG_DATA_HOME || path.join(homedir, '.local', 'share'), appName);
    }
}
