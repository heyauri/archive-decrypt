const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class ProgressManager {
    constructor(archivePath, progressDir = '.progress') {
        this.archivePath = archivePath;
        this.progressDir = progressDir;
        this.archiveHash = this._generateArchiveHash();
        this.progressFile = path.join(this.progressDir, `${this.archiveHash}.json`);
        
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
        fs.writeFileSync(this.progressFile, JSON.stringify(progressData, null, 2));
        return progressData;
    }

    loadProgress() {
        if (!fs.existsSync(this.progressFile)) {
            return null;
        }
        try {
            const data = fs.readFileSync(this.progressFile, 'utf8');
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
