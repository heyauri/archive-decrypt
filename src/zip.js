const AdmZip = require('adm-zip');
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

    async decryptFile(file, password) {
        try {
            await this.zip.readFile(file, password);
            return {
                status: true,
                file,
                message: 'success'
            };
        } catch (error) {
            if (error.message === "ADM-ZIP: Wrong Password") {
                return {
                    status: false,
                    file,
                    message: 'password_error'
                };
            } else {
                console.error('Error during extraction:', error.message);
                return {
                    status: false,
                    file,
                    message: 'unexpected_error',
                    extra: error.message
                }
            }
        }
    }
}

module.exports = ZipDecrypt;
