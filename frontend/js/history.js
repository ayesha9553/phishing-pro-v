/**
 * PhishingPro — History Page
 */

const HistoryPage = {
    _currentPage: 0,
    _pageSize: 20,
    _filters: { riskLevel: '', source: '' },

    render() {
        return `
            <div class="page-header">
                <h1 class="page-title">Scan History</h1>
                <p class="page-subtitle">Review past email analysis results</p>
            </div>

            <div class="card">
                <div class="filter-bar">
                    <select id="filter-risk">
                        <option value="">All Risk Levels</option>
                        <option value="safe">Safe</option>
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                    </select>
                    <select id="filter-source">
                        <option value="">All Sources</option>
                        <option value="upload">File Upload</option>
                        <option value="paste">Paste</option>
                    </select>
                    <div style="flex:1"></div>
                    <button class="btn btn-danger btn-sm" id="clear-history-btn">🗑️ Clear All</button>
                </div>

                <div id="history-table-container">
                    <div class="loading-overlay">
                        <div class="spinner"></div>
                        <span>Loading history...</span>
                    </div>
                </div>

                <div class="pagination" id="pagination"></div>
            </div>

            <!-- Detail Modal -->
            <div id="history-detail-container" style="display:none"></div>
        `;
    },

    async mount() {
        this._setupFilters();
        this._setupClear();
        await this._loadHistory();

        // Check for scan detail in hash (#/history/123)
        const match = location.hash.match(/#\/history\/(\d+)/);
        if (match) {
            await this._showDetail(parseInt(match[1]));
        }
    },

    _setupFilters() {
        const riskFilter = document.getElementById('filter-risk');
        const sourceFilter = document.getElementById('filter-source');

        if (riskFilter) {
            riskFilter.addEventListener('change', () => {
                this._filters.riskLevel = riskFilter.value;
                this._currentPage = 0;
                this._loadHistory();
            });
        }

        if (sourceFilter) {
            sourceFilter.addEventListener('change', () => {
                this._filters.source = sourceFilter.value;
                this._currentPage = 0;
                this._loadHistory();
            });
        }
    },

    _setupClear() {
        const btn = document.getElementById('clear-history-btn');
        if (btn) {
            btn.addEventListener('click', async () => {
                if (confirm('Are you sure you want to clear all scan history? This cannot be undone.')) {
                    try {
                        await API.clearHistory();
                        App.toast('History cleared', 'success');
                        await this._loadHistory();
                    } catch (err) {
                        App.toast(`Failed: ${err.message}`, 'error');
                    }
                }
            });
        }
    },

    async _loadHistory() {
        const container = document.getElementById('history-table-container');
        if (!container) return;

        try {
            const data = await API.getHistory({
                limit: this._pageSize,
                offset: this._currentPage * this._pageSize,
                riskLevel: this._filters.riskLevel || undefined,
                source: this._filters.source || undefined,
            });

            if (data.scans.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">📭</div>
                        <div class="empty-state-title">No scans found</div>
                        <div class="empty-state-text">
                            ${this._filters.riskLevel || this._filters.source
                                ? 'No scans match the current filters.'
                                : 'Start scanning emails to build your history.'}
                        </div>
                        <a href="#/scan" class="btn btn-primary btn-sm">Start Scanning</a>
                    </div>
                `;
                document.getElementById('pagination').innerHTML = '';
                return;
            }

            container.innerHTML = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Subject</th>
                            <th>Sender</th>
                            <th>Risk</th>
                            <th>Score</th>
                            <th>Source</th>
                            <th>Date</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.scans.map(s => `
                            <tr>
                                <td class="cell-subject" style="cursor:pointer" onclick="HistoryPage._showDetail(${s.id})">${this._esc(s.subject || '(no subject)')}</td>
                                <td class="cell-sender">${this._esc(s.sender || '—')}</td>
                                <td><span class="risk-badge ${s.risk_level}">${s.risk_level}</span></td>
                                <td class="cell-score">${s.risk_score}</td>
                                <td><span style="color:var(--text-muted);font-size:0.8rem">${s.source}</span></td>
                                <td class="cell-date">${this._formatDate(s.created_at)}</td>
                                <td>
                                    <button class="btn btn-secondary btn-sm" onclick="HistoryPage._deleteScan(${s.id})" title="Delete">
                                        🗑️
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;

            this._renderPagination(data.total);
        } catch (err) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">⚠️</div>
                    <div class="empty-state-title">Error loading history</div>
                    <div class="empty-state-text">${err.message}</div>
                </div>
            `;
        }
    },

    _renderPagination(total) {
        const container = document.getElementById('pagination');
        if (!container) return;

        const totalPages = Math.ceil(total / this._pageSize);
        if (totalPages <= 1) {
            container.innerHTML = '';
            return;
        }

        container.innerHTML = `
            <button ${this._currentPage === 0 ? 'disabled' : ''} onclick="HistoryPage._goToPage(${this._currentPage - 1})">← Prev</button>
            <span class="page-info">${this._currentPage + 1} / ${totalPages}</span>
            <button ${this._currentPage >= totalPages - 1 ? 'disabled' : ''} onclick="HistoryPage._goToPage(${this._currentPage + 1})">Next →</button>
        `;
    },

    async _goToPage(page) {
        this._currentPage = page;
        await this._loadHistory();
    },

    async _showDetail(scanId) {
        try {
            const scan = await API.getScanDetail(scanId);
            const container = document.getElementById('history-detail-container');
            if (!container) return;

            container.style.display = 'block';
            container.scrollIntoView({ behavior: 'smooth' });

            const riskColor = ScannerPage._getRiskColor(scan.risk_level);
            const circumference = 2 * Math.PI * 70;
            const offset = circumference - (scan.risk_score / 100) * circumference;
            const grouped = { header: [], url: [], content: [], auth: [] };
            (scan.findings || []).forEach(f => {
                if (grouped[f.category]) grouped[f.category].push(f);
            });

            container.innerHTML = `
                <div class="card scan-result" style="margin-top:var(--space-lg)">
                    <div class="card-header">
                        <span class="card-title">Scan Detail #${scan.id}</span>
                        <div style="display:flex;gap:var(--space-sm)">
                            <button class="btn btn-secondary btn-sm" id="export-detail-btn">📥 Export</button>
                            <button class="btn btn-secondary btn-sm" onclick="document.getElementById('history-detail-container').style.display='none'">✕ Close</button>
                        </div>
                    </div>
                    <div class="scan-result-header">
                        <div class="risk-ring-container">
                            <div class="risk-ring">
                                <svg viewBox="0 0 160 160">
                                    <circle class="ring-bg" cx="80" cy="80" r="70"/>
                                    <circle class="ring-fill" cx="80" cy="80" r="70"
                                        stroke="${riskColor}"
                                        stroke-dasharray="${circumference}"
                                        stroke-dashoffset="${offset}"/>
                                </svg>
                                <div class="ring-score">
                                    <div class="score-value" style="color:${riskColor}">${scan.risk_score}</div>
                                    <div class="score-label">Risk Score</div>
                                </div>
                            </div>
                            <span class="risk-badge ${scan.risk_level}">${scan.risk_level}</span>
                        </div>
                        <div class="scan-result-meta">
                            <h3>${ScannerPage._esc(scan.subject || '(no subject)')}</h3>
                            <div class="meta-row"><span class="meta-label">From:</span><span class="meta-value">${ScannerPage._esc(scan.sender || '—')}</span></div>
                            <div class="meta-row"><span class="meta-label">To:</span><span class="meta-value">${ScannerPage._esc(scan.recipient || '—')}</span></div>
                            <div class="meta-row"><span class="meta-label">Date:</span><span class="meta-value">${ScannerPage._esc(scan.email_date || '—')}</span></div>
                        </div>
                    </div>

                    ${scan.body_preview ? `
                    <div style="margin-bottom:var(--space-lg)">
                        <div class="card-header" style="margin-bottom:var(--space-sm)">
                            <span class="card-title">📄 Body Preview</span>
                        </div>
                        <div class="body-preview-content">${ScannerPage._esc(scan.body_preview)}</div>
                    </div>
                    ` : ''}

                    ${ScannerPage._renderFindingsGroups(grouped)}
                </div>
            `;

            document.getElementById('export-detail-btn')?.addEventListener('click', async () => {
                try {
                    await API.exportScan(scan.id);
                    App.toast('Report downloaded', 'success');
                } catch (err) {
                    App.toast(`Export failed: ${err.message}`, 'error');
                }
            });
        } catch (err) {
            App.toast(`Failed to load scan: ${err.message}`, 'error');
        }
    },

    async _deleteScan(scanId) {
        if (!confirm('Delete this scan?')) return;
        try {
            await API.deleteScan(scanId);
            App.toast('Scan deleted', 'success');
            await this._loadHistory();
        } catch (err) {
            App.toast(`Failed: ${err.message}`, 'error');
        }
    },

    _esc(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    _formatDate(dateStr) {
        if (!dateStr) return '—';
        try {
            const d = new Date(dateStr);
            return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
        } catch {
            return dateStr;
        }
    }
};
