const AdmZip = require('adm-zip');
const { generatePasswords } = require('./utils');
const ArchiveDecrypt = require('./ArchiveDecrypt');

class ZipDecrypt extends ArchiveDecrypt {
    constructor(zipPath) {
        super(zipPath);
        this.zip = new AdmZip(zipPath);
        this.entries = this.zip.getEntries();
    }

    initializeTargetFile() {
        this.targetFile = null;
        this.targetFileNotFound = false;

        if (this.options.targetFileName) {
            for (const entry of this.entries) {
                if (!entry.isDirectory && entry.entryName === this.options.targetFileName) {
                    this.targetFile = entry;
                    break;
                }
            }

            if (!this.targetFile) {
                this.targetFileNotFound = true;
                throw new Error(`Target file ${this.options.targetFileName} not found in archive`);
            }
        } else {
            if (this.entries.length > 0) {
                for (const entry of this.entries) {
                    if (!entry.isDirectory) {
                        this.targetFile = entry;
                        break;
                    }
                }
            }
        }
    }

    async tryPassword(password) {
        if (this.currentDecryptingMode !== 'bruteForce') {
            const cached = this.getCachedResult(password);
            if (cached !== undefined) {
                return cached;
            }
        }

        if (this.targetFileNotFound) {
            throw new Error(`Target file ${this.options.targetFileName} not found in archive`);
        }

        if (!this.targetFile) {
            return false;
        }

        try {
            this.zip.readFile(this.targetFile, password);
            this.setCache(password, true);
            return true;
        } catch (error) {
            if (this.currentDecryptingMode !== 'bruteForce') {
                this.setCache(password, false);
            }
            return false;
        }
    }

    async bruteForceAttack(options = {}) {
        this.checkOptions(options);
        this.options = options;
        const {
            charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            minLength = 1,
            maxLength = 10,
            maxAttempts = Infinity,
            delay = 0,
            onAttempt = null,
            onSuccess = null,
            onFailure = null
        } = options;
        this.currentDecryptingMode = 'bruteForce';
        const safeDelay = this.validateDelay(delay);

        this.initializeTargetFile();
        if (this.targetFileNotFound) {
            console.error(`Target file ${this.options.targetFileName} not found in archive`);
            if (onFailure) onFailure();
            return null;
        }

        let attempts = 0;

        for (const password of generatePasswords(charset, minLength, maxLength, maxAttempts)) {
            attempts++;
            if (onAttempt) onAttempt(password, attempts);

            try {
                const result = await this.tryPassword(password);
                if (result) {
                    if (onSuccess) onSuccess(password, attempts);
                    return password;
                }
            } catch (error) {
                if (this.isTargetFileError(error)) {
                    console.error(error.message);
                    if (onFailure) onFailure();
                    return null;
                }
            }

            if (safeDelay > 0) {
                await new Promise(resolve => setTimeout(resolve, safeDelay));
            }
        }

        if (onFailure) onFailure();
        return null;
    }
}

module.exports = ZipDecrypt;
