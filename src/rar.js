const unrar = require('node-unrar-js');
const fs = require('fs');
const { generatePasswords } = require('./utils');
const ArchiveDecrypt = require('./ArchiveDecrypt');

class RarDecrypt extends ArchiveDecrypt {
    constructor(rarPath) {
        super(rarPath);
        this.buffer = Uint8Array.from(fs.readFileSync(rarPath)).buffer;
        this.targetFile = null;
        this.targetFileInitialized = false;
        this.rarExtractor = null;
    }

    async initializeTargetFile() {
        if (this.targetFileInitialized) return;

        try {
            const extractor = await unrar.createExtractorFromData({
                data: this.buffer
            });
            this.rarExtractor = extractor;

            const list = extractor.getFileList();
            const fileHeaders = [...list.fileHeaders];

            let smallestSize = Infinity;
            let targetFile = null;
            for (const header of fileHeaders) {
                if (!header.flags.directory && header.flags.encrypted) {
                    if (this.options.targetFileName && header.name === this.options.targetFileName) {
                        targetFile = header.name;
                        smallestSize = header.packSize;
                        break;
                    } else if (!this.options.targetFileName) {
                        if (header.packSize < smallestSize) {
                            smallestSize = header.packSize;
                            targetFile = header.name;
                        }
                    }
                }
            }
            if (this.options.targetFileName && !targetFile) {
                this.targetFileNotFound = true;
                this.targetFileInitialized = true;
                throw new Error(`Target file ${this.options.targetFileName} not found in archive`);
            }
            this.targetFile = targetFile;
            console.log(`Target encrypted file found: ${targetFile} (size: ${smallestSize})`);
            this.targetFileInitialized = true;
        } catch (error) {
            console.error('Error initializing target file:', error.message);
            this.targetFileInitialized = true;
        }
    }

    async tryPassword(password) {
        password = password.trim();

        if (this.currentDecryptingMode !== 'bruteForce') {
            const cached = this.getCachedResult(password);
            if (cached !== undefined) {
                return cached;
            }
        }


        if (this.targetFileNotFound) {
            throw new Error(`Target file ${this.options.targetFileName} not found in archive`);
        }

        try {
            if (this.targetFile) {
                const result = this.rarExtractor.extract({
                    files: [this.targetFile],
                    password: password
                });
                const files = [...result.files];
            } else {
                const result = this.rarExtractor.extract();
                const files = [...result.files];
            }

            this.setCache(password, true);
            return true;
        } catch (error) {
            if (error.reason === 'ERAR_BAD_PASSWORD' ||
                (error.message && (error.message.includes('bad password') || error.message.includes('Bad password')))) {
                if (this.currentDecryptingMode !== 'bruteForce') {
                    this.setCache(password, false);
                }
                return false;
            } else {
                console.error('Error during extraction:', error.message);
                return false;
            }
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

        await this.initializeTargetFile();
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
                if (!(error.reason === 'ERAR_BAD_PASSWORD' ||
                    (error.message && (error.message.includes('bad password') || error.message.includes('Bad password'))))) {
                    console.error('Error during extraction:', error.message);
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

module.exports = RarDecrypt;
