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
            // Choose the smallest file to speed up validation
            let smallestSize = Infinity;
            for (const entry of this.entries) {
                if (!entry.isDirectory && entry.header.size < smallestSize) {
                    smallestSize = entry.header.size;
                    this.targetFile = entry;
                }
            }
            if (this.targetFile) {
                console.log(`Target file found: ${this.targetFile.entryName} (size: ${smallestSize})`);
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
            // In some cases, the error password may cause the zlib to throw a Z_DATA_ERROR error
            if (error.message === 'ADM-ZIP: Wrong Password'
                || error.code === 'Z_DATA_ERROR'
                || error.message.includes('invalid stored block lengths')
                || error.message.includes('too many length or distance codes')
                || error.message.includes('CRC32 checksum failed')
                || error.message.includes('unexpected end of file')
            ) {
                return {
                    status: false,
                    file,
                    message: 'password_error'
                };
            } else {
                console.error(error)
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
