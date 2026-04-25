const AdmZip = require('adm-zip');
const { generatePasswords } = require('./utils');
const ArchiveDecrypt = require('./ArchiveDecrypt');

class ZipDecrypt extends ArchiveDecrypt {
    constructor(zipPath) {
        super(zipPath);
        this.zip = new AdmZip(zipPath);
        this.targetEntry = null;
        this.targetFileNotFound = false;
        this.entries = this.zip.getEntries();
    }

    initializeTargetFile() {
        this.targetEntry = null;
        this.targetFileNotFound = false;
        
        if (this.options.targetFileName) {
            for (const entry of this.entries) {
                if (!entry.isDirectory && entry.entryName === this.options.targetFileName) {
                    this.targetEntry = entry;
                    break;
                }
            }
            
            if (!this.targetEntry) {
                this.targetFileNotFound = true;
                throw new Error(`Target file ${this.options.targetFileName} not found in archive`);
            }
        } else {
            if (this.entries.length > 0) {
                for (const entry of this.entries) {
                    if (!entry.isDirectory) {
                        this.targetEntry = entry;
                        break;
                    }
                }
            }
        }
    }

    async tryPassword(password) {
        if (this.currentDecryptingMode !== 'bruteForce' && this.extractorCache.has(password)) {
            return this.extractorCache.get(password);
        }
        
        if (this.targetFileNotFound) {
            throw new Error(`Target file ${this.options.targetFileName} not found in archive`);
        }
        
        if (!this.targetEntry) {
            return false;
        }
        
        try {
            this.zip.readFile(this.targetEntry, password);
            this.extractorCache.set(password, true);
            return true;
        } catch (error) {
            if (this.currentDecryptingMode !== 'bruteForce') {
                this.extractorCache.set(password, false);
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
                if (error.message && error.message.includes('not found in archive')) {
                    console.error(error.message);
                    if (onFailure) onFailure();
                    return null;
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

module.exports = ZipDecrypt;
