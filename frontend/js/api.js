/**
 * PhishingPro — API Client
 * Fetch wrapper for all backend API calls.
 */

const API = {
    BASE_URL: '',

    async _request(method, path, { body, isFormData } = {}) {
        const options = {
            method,
            headers: {},
        };

        if (body && !isFormData) {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        } else if (body && isFormData) {
            options.body = body;
        }

        try {
            const response = await fetch(`${this.BASE_URL}${path}`, options);
            if (!response.ok) {
                const err = await response.json().catch(() => ({ detail: response.statusText }));
                throw new Error(err.detail || `HTTP ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            if (error instanceof TypeError && error.message.includes('fetch')) {
                throw new Error('Cannot connect to server. Is the backend running?');
            }
            throw error;
        }
    },

    // ── Scan endpoints ──────────────────────────────────────────────────────
    async scanUpload(file) {
        const formData = new FormData();
        formData.append('file', file);
        return this._request('POST', '/api/scan/upload', { body: formData, isFormData: true });
    },

    async scanText(rawEmail) {
        return this._request('POST', '/api/scan/text', { body: { raw_email: rawEmail } });
    },

    async getScan(scanId) {
        return this._request('GET', `/api/scan/${scanId}`);
    },

    async exportScan(scanId) {
        const response = await fetch(`${this.BASE_URL}/api/scan/${scanId}/export`);
        if (!response.ok) throw new Error('Failed to export report');
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `phishingpro_report_${scanId}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },

    // ── History endpoints ───────────────────────────────────────────────────
    async getHistory({ limit = 50, offset = 0, riskLevel, source } = {}) {
        const params = new URLSearchParams({ limit, offset });
        if (riskLevel) params.append('risk_level', riskLevel);
        if (source) params.append('source', source);
        return this._request('GET', `/api/history?${params}`);
    },

    async getStats() {
        return this._request('GET', '/api/history/stats');
    },

    async getScanDetail(scanId) {
        return this._request('GET', `/api/history/${scanId}`);
    },

    async deleteScan(scanId) {
        return this._request('DELETE', `/api/history/${scanId}`);
    },

    async clearHistory() {
        return this._request('DELETE', '/api/history');
    },

    // ── Settings endpoints ──────────────────────────────────────────────────
    async getSettings() {
        return this._request('GET', '/api/settings');
    },

    async updateSettings(settings) {
        return this._request('PUT', '/api/settings', { body: settings });
    },

    // ── Threat Intelligence endpoints ───────────────────────────────────────
    async checkUrlIntel(url) {
        const params = new URLSearchParams({ url });
        return this._request('GET', `/api/intel/check?${params}`);
    },

    async checkDomainReputation(domain) {
        const params = new URLSearchParams({ domain });
        return this._request('GET', `/api/intel/domain?${params}`);
    },

    async getFeedStatus() {
        return this._request('GET', '/api/intel/feed-status');
    },

    async submitReport({ scanId, reporterEmail, reportType, comment }) {
        return this._request('POST', '/api/intel/report', {
            body: {
                scan_id: scanId,
                reporter_email: reporterEmail || '',
                report_type: reportType,
                comment,
            },
        });
    },

    async getUserReports(limit = 50) {
        return this._request('GET', `/api/intel/reports?limit=${limit}`);
    },

    // ── AI Analysis endpoints ───────────────────────────────────────────────
    async getAiAnalysis(scanId) {
        return this._request('POST', '/api/ai/analyze', { body: { scan_id: scanId } });
    },

    async getAiStatus() {
        return this._request('GET', '/api/ai/status');
    },

    async summarizeIndicators(indicators, context = '') {
        return this._request('POST', '/api/ai/summarize', {
            body: { indicators, context },
        });
    },

    // ── Gateway endpoints ───────────────────────────────────────────────────
    async getGatewayLogs(limit = 100) {
        return this._request('GET', `/api/gateway/logs?limit=${limit}`);
    },

    async getGatewayStats() {
        return this._request('GET', '/api/gateway/stats');
    },

    async getGatewayConfig() {
        return this._request('GET', '/api/gateway/config');
    },

    async updateGatewayConfig({ quarantineThreshold, blockThreshold }) {
        const body = {};
        if (quarantineThreshold !== undefined) body.quarantine_threshold = quarantineThreshold;
        if (blockThreshold !== undefined) body.block_threshold = blockThreshold;
        return this._request('PUT', '/api/gateway/config', { body });
    },

    async ingestEmail({ rawEmail, sourceIp, envelopeFrom, envelopeTo }) {
        return this._request('POST', '/api/gateway/ingest', {
            body: {
                raw_email: rawEmail,
                source_ip: sourceIp || '',
                envelope_from: envelopeFrom || '',
                envelope_to: envelopeTo || '',
            },
        });
    },
};
