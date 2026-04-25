const unrar = require('node-unrar-js');
const fs = require('fs');
const { generatePasswords } = require('./utils');
const ArchiveDecrypt = require('./ArchiveDecrypt');

class RarDecrypt extends ArchiveDecrypt {
    constructor(rarPath) {
        super(rarPath);
        this.buffer = Uint8Array.from(fs.readFileSync(rarPath)).buffer;
    }

    // Try to decrypt with password
    async tryPassword(password) {
        // Check if extractor instance for this password already exists in cache
        if (this.extractorCache.has(password)) {
            return this.extractorCache.get(password);
        }

        try {
            // Try to extract with password
            const extractor = await unrar.createExtractorFromData({ 
                data: this.buffer, 
                password: password 
            });
            
            // Try to get file list
            const list = extractor.getFileList();
            // Iterate through file list to trigger extraction
            const fileHeaders = [...list.fileHeaders];
            
            // If successfully get file list, password is correct
            const result = fileHeaders.length > 0;
            // Cache result
            this.extractorCache.set(password, result);
            return result;
        } catch (error) {
            // Password error will throw exception
            if (error.reason === unrar.FailReason.ERAR_BAD_PASSWORD) {
                // Cache failure result
                this.extractorCache.set(password, false);
                return false;
            } else {
                // Other errors, possibly file corruption
                console.error('Error during extraction:', error.message);
                return false;
            }
        }
    }

    // Brute force attack
    async bruteForceAttack(options = {}) {
        const {
            charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            minLength = 1,
            maxLength = 6,
            maxAttempts = Infinity,
            delay = 0,
            onAttempt = null,
            onSuccess = null,
            onFailure = null
        } = options;

        let attempts = 0;

        // Use common password generator
        for (const password of generatePasswords(charset, minLength, maxLength, maxAttempts)) {
            attempts++;
            if (onAttempt) onAttempt(password, attempts);

            try {
                // Brute force attack doesn't use cache, try password directly
                const extractor = await unrar.createExtractorFromData({ 
                    data: this.buffer, 
                    password: password 
                });
                
                // Try to get file list
                const list = extractor.getFileList();
                // Iterate through file list to trigger extraction
                const fileHeaders = [...list.fileHeaders];
                
                // If successfully get file list, password is correct
                if (fileHeaders.length > 0) {
                    if (onSuccess) onSuccess(password, attempts);
                    return password;
                }
            } catch (error) {
                // Password error will throw exception, continue trying
                if (error.reason !== unrar.FailReason.ERAR_BAD_PASSWORD) {
                    // Other errors, possibly file corruption
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