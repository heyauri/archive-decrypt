const unrar = require('node-unrar-js');
const fs = require('fs');
const { generatePasswords } = require('./utils');
const ArchiveDecrypt = require('./ArchiveDecrypt');

class RarDecrypt extends ArchiveDecrypt {
    constructor(rarPath) {
        super(rarPath);
        this.buffer = Uint8Array.from(fs.readFileSync(rarPath)).buffer;
        this.smallestEncryptedFileName = null;
        this.smallestEncryptedFileInitialized = false;
    }

    // Find the smallest encrypted file for testing password
    async initializeSmallestEncryptedFile() {
        if (this.smallestEncryptedFileInitialized) return;

        try {
            const extractor = await unrar.createExtractorFromData({
                data: this.buffer
            });

            const list = extractor.getFileList();
            const fileHeaders = [...list.fileHeaders];

            let smallestSize = Infinity;
            for (const header of fileHeaders) {
                if (!header.flags.directory && header.flags.encrypted) {
                    if (header.packSize < smallestSize) {
                        smallestSize = header.packSize;
                        this.smallestEncryptedFileName = header.name;
                    }
                }
            }
            console.log(`Smallest encrypted file found: ${this.smallestEncryptedFileName} (size: ${smallestSize})`);
            this.smallestEncryptedFileInitialized = true;
        } catch (error) {
            console.error('Error initializing smallest encrypted file:', error.message);
            this.smallestEncryptedFileInitialized = true;
        }
    }

    // Try to decrypt with password
    async tryPassword(password) {
        // Remove any trailing whitespace (like \r from Windows line endings)
        password = password.trim();

        // Check if extractor instance for this password already exists in cache
        if (this.currentDecryptingMode !== 'bruteForce' && this.extractorCache.has(password)) {
            return this.extractorCache.get(password);
        }

        // Initialize smallest encrypted file if not already done
        await this.initializeSmallestEncryptedFile();

        try {
            // Use the correct API for node-unrar-js
            // createExtractorFromData is async
            const extractor = await unrar.createExtractorFromData({
                data: this.buffer,
                password: password
            });

            // Try to extract the smallest encrypted file to verify password
            if (this.smallestEncryptedFileName) {
                // Extract just the smallest encrypted file
                const result = extractor.extract({
                    files: [this.smallestEncryptedFileName],
                    password: password
                });
                // Iterate to trigger extraction
                const files = [...result.files];
            } else {
                // If no encrypted file found, extract all to verify
                const result = extractor.extract();
                const files = [...result.files];
            }

            // If no error is thrown, password is correct

            this.extractorCache.set(password, true);
            return true;
        } catch (error) {
            // Password error will throw exception
            if (error.reason === 'ERAR_BAD_PASSWORD' || error.message.includes('bad password') || error.message.includes('Bad password')) {
                // Cache failure result (except for brute force)
                if (this.currentDecryptingMode !== 'bruteForce') {
                    this.extractorCache.set(password, false);
                }
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
            charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.',
            minLength = 1,
            maxLength = 10,
            maxAttempts = Infinity,
            delay = 0,
            onAttempt = null,
            onSuccess = null,
            onFailure = null
        } = options;
        this.currentDecryptingMode = 'bruteForce';

        let attempts = 0;

        // Use common password generator
        for (const password of generatePasswords(charset, minLength, maxLength, maxAttempts)) {
            attempts++;
            if (onAttempt) onAttempt(password, attempts);

            try {
                // Brute force attack uses tryPassword method
                const result = await this.tryPassword(password);
                if (result) {
                    if (onSuccess) onSuccess(password, attempts);
                    return password;
                }
            } catch (error) {
                // Password error will throw exception, continue trying
                if (!(error.reason === 'ERAR_BAD_PASSWORD' || error.message.includes('bad password'))) {
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