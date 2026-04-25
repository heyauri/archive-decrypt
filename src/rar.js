const unrar = require('node-unrar-js');
const fs = require('fs');
const { generatePasswords } = require('./utils');
const ArchiveDecrypt = require('./ArchiveDecrypt');

class RarDecrypt extends ArchiveDecrypt {
    constructor(rarPath) {
        super(rarPath);
        this.buffer = Uint8Array.from(fs.readFileSync(rarPath)).buffer;
        this.targetEncryptedFileName = null;
        this.targetEncryptedFileInitialized = false;
        this.rarExtractor = null;
        this.targetFileNotFound = false;
    }

    async initializeTargetFile() {
        if (this.targetEncryptedFileInitialized) return;

        try {
            const extractor = await unrar.createExtractorFromData({
                data: this.buffer
            });
            this.rarExtractor = extractor;

            const list = extractor.getFileList();
            const fileHeaders = [...list.fileHeaders];

            let targetFileSize = Infinity;
            let targetFileName = null;
            for (const header of fileHeaders) {
                if (!header.flags.directory && header.flags.encrypted) {
                    if (this.options.targetFileName && header.name === this.options.targetFileName) {
                        targetFileName = header.name;
                        targetFileSize = header.packSize;
                        break;
                    } else if (!this.options.targetFileName) {
                        if (header.packSize < targetFileSize) {
                            targetFileSize = header.packSize;
                            targetFileName = header.name;
                        }
                    }
                }
            }
            if (this.options.targetFileName && !targetFileName) {
                this.targetFileNotFound = true;
                this.targetEncryptedFileInitialized = true;
                throw new Error(`Target file ${this.options.targetFileName} not found in archive`);
            }
            this.targetEncryptedFileName = targetFileName;
            console.log(`Target encrypted file found: ${targetFileName} (size: ${targetFileSize})`);
            this.targetEncryptedFileInitialized = true;
        } catch (error) {
            console.error('Error initializing target encrypted file:', error.message);
            this.targetEncryptedFileInitialized = true;
        }
    }

    async tryPassword(password) {
        password = password.trim();

        if (this.currentDecryptingMode !== 'bruteForce' && this.extractorCache.has(password)) {
            return this.extractorCache.get(password);
        }

        if (this.targetFileNotFound) {
            throw new Error(`Target file ${this.options.targetFileName} not found in archive`);
        }

        try {
            if (this.targetEncryptedFileName) {
                const result = this.rarExtractor.extract({
                    files: [this.targetEncryptedFileName],
                    password: password
                });
                const files = [...result.files];
            } else {
                const result = this.rarExtractor.extract();
                const files = [...result.files];
            }

            this.extractorCache.set(password, true);
            return true;
        } catch (error) {
            if (error.reason === 'ERAR_BAD_PASSWORD' || 
                (error.message && (error.message.includes('bad password') || error.message.includes('Bad password')))) {
                if (this.currentDecryptingMode !== 'bruteForce') {
                    this.extractorCache.set(password, false);
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

            if (delay > 0) {
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }

        if (onFailure) onFailure();
        return null;
    }
}

module.exports = RarDecrypt;
