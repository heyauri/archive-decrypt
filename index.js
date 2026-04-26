const path = require('path');
const ZipDecrypt = require('./src/zip');
const RarDecrypt = require('./src/rar');

class ArchiveDecrypt {
    constructor(archivePath) {
        this.archivePath = archivePath;
        const ext = path.extname(archivePath).toLowerCase();

        if (ext === '.zip') {
            this.decryptor = new ZipDecrypt(archivePath);
        } else if (ext === '.rar') {
            this.decryptor = new RarDecrypt(archivePath);
        } else {
            throw new Error(`Unsupported archive format: ${ext}`);
        }
    }

    // Dictionary attack
    async dictionaryAttack(options = {}) {
        return this.decryptor.dictionaryAttack(options);
    }

    // Brute force attack
    async bruteForceAttack(options = {}) {
        return this.decryptor.bruteForceAttack(options);
    }

    // Hybrid attack (dictionary + brute force)
    async hybridAttack(options = {}) {
        return this.decryptor.hybridAttack(options);
    }
}

// Export module
module.exports = ArchiveDecrypt;
