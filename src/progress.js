const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class ProgressManager {
    constructor(archivePath, progressDir = '.progress') {
        this.archivePath = archivePath;
        this.progressDir = progressDir;
        this.archiveHash = this._generateArchiveHash();
        this.progressFile = path.join(this.progressDir, `${this.archiveHash}.json`);
        this.savePromise = Promise.resolve();
        
        if (!fs.existsSync(this.progressDir)) {
            fs.mkdirSync(this.progressDir, { recursive: true });
        }
    }

    _generateArchiveHash() {
        const stats = fs.statSync(this.archivePath);
        const hashInput = `${this.archivePath}-${stats.size}-${stats.mtimeMs}`;
        return crypto.createHash('md5').update(hashInput).digest('hex');
    }

    saveProgress(data) {
        const progressData = {
            ...data,
            timestamp: Date.now(),
            archivePath: this.archivePath
        };
        
        // Use synchronous write for reliability to avoid empty/corrupted files
        try {
            fs.writeFileSync(this.progressFile, JSON.stringify(progressData, null, 2));
        } catch (err) {
            console.warn('Failed to save progress:', err);
        }
    }

    loadProgress() {
        if (!fs.existsSync(this.progressFile)) {
            return null;
        }
        try {
            const data = fs.readFileSync(this.progressFile, 'utf8');
            if (!data || data.trim() === '') {
                console.warn('Progress file is empty, ignoring');
                return null;
            }
            return JSON.parse(data);
        } catch (error) {
            console.warn('Failed to load progress file:', error.message);
            return null;
        }
    }

    clearProgress() {
        if (fs.existsSync(this.progressFile)) {
            fs.unlinkSync(this.progressFile);
        }
    }

    hasProgress() {
        return fs.existsSync(this.progressFile);
    }
}

module.exports = ProgressManager;
