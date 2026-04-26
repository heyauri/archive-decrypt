const unrar = require('node-unrar-js');
const fs = require('fs');
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

    async decryptFile(file, password) {
        try {
            const result = await this.rarExtractor.extract({
                files: [file],
                password: password
            });
            // IMPORTANT: if ignore this step, the error will not be thrown, and the password will be considered as correct
            let files = [...result.files];
            return {
                status: true,
                file,
                message: 'success'
            }
        } catch (error) {
            if (error.reason === 'ERAR_BAD_PASSWORD') {
                return {
                    status: false,
                    file,
                    message: 'password_error'
                }
            } else {
                console.error('Error during extraction:',error.reason, error.message);
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

module.exports = RarDecrypt;
