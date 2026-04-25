const AdmZip = require('adm-zip');
const { generatePasswords } = require('./utils');
const ArchiveDecrypt = require('./ArchiveDecrypt');

class ZipDecrypt extends ArchiveDecrypt {
    constructor(zipPath) {
        super(zipPath);
        this.zip = new AdmZip(zipPath);
        this.firstEntry = null;
        
        // Cache the first file entry to avoid repeated retrieval
        const entries = this.zip.getEntries();
        if (entries.length > 0) {
            this.firstEntry = entries[0];
        }
    }

    // Try to decrypt with password
    async tryPassword(password) {
        if (!this.firstEntry) {
            return false;
        }
        
        try {
            // Try to read file content, will throw exception if password is wrong
            this.zip.readFile(this.firstEntry, password);
            // If successfully read, password is correct
            return true;
        } catch (error) {
            // Password error will throw exception
            return false;
        }
    }

    // Brute force attack
    async bruteForceAttack(options = {}) {
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