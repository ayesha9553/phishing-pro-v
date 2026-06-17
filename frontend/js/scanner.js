/**
 * PhishingPro — Scanner Page
 */

const ScannerPage = {
    _scanResult: null,

    render() {
        return `
            <div class="page-header">
                <h1 class="page-title">Scan Email</h1>
                <p class="page-subtitle">Upload an email file or paste raw email content for phishing analysis</p>
            </div>

            <div class="card" id="scan-input-card">
                <div class="tabs">
                    <button class="tab-btn active" data-tab="upload" id="tab-btn-upload">📎 Upload File</button>
                    <button class="tab-btn" data-tab="paste" id="tab-btn-paste">📝 Paste Email</button>
                </div>

                <div class="tab-content active" id="tab-upload">
                    <div class="drop-zone" id="drop-zone">
                        <div class="drop-zone-icon">📧</div>
                        <div class="drop-zone-text">Drag & drop an email file here</div>
                        <div class="drop-zone-hint">Supports .eml and .msg files (up to 25MB)</div>
                        <input type="file" id="file-input" accept=".eml,.msg">
                    </div>
                    <div style="text-align:center;margin-top:var(--space-md)">
                        <button class="btn btn-secondary btn-sm" id="browse-btn">Browse Files</button>
                    </div>
                </div>

                <div class="tab-content" id="tab-paste">
                    <textarea class="email-textarea" id="email-text" 
                        placeholder="Paste the complete email content here, including all headers...

Example:
From: sender@example.com
To: recipient@example.com
Subject: Important Notice
Date: Mon, 10 Jun 2025 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain

Dear Customer,
Your account has been suspended..."></textarea>
                    <div style="margin-top:var(--space-md);display:flex;justify-content:flex-end">
                        <button class="btn btn-primary btn-lg" id="scan-text-btn">
                            🔍 Analyze Email
                        </button>
                    </div>
                </div>
            </div>

            <!-- Scan Progress -->
            <div class="card" id="scan-progress-card" style="display:none">
                <div class="scan-progress" id="scan-progress">
                    <div class="scan-step" data-step="parse">
                        <div class="scan-step-line"></div>
                        <div class="scan-step-dot">📨</div>
                        <div class="scan-step-label">Parsing</div>
                    </div>
                    <div class="scan-step" data-step="headers">
                        <div class="scan-step-line"></div>
                        <div class="scan-step-dot">📋</div>
                        <div class="scan-step-label">Headers</div>
                    </div>
                    <div class="scan-step" data-step="urls">
                        <div class="scan-step-line"></div>
                        <div class="scan-step-dot">🔗</div>
                        <div class="scan-step-label">URLs</div>
                    </div>
                    <div class="scan-step" data-step="content">
                        <div class="scan-step-line"></div>
                        <div class="scan-step-dot">📝</div>
                        <div class="scan-step-label">Content</div>
                    </div>
                    <div class="scan-step" data-step="auth">
                        <div class="scan-step-dot">🔐</div>
                        <div class="scan-step-label">Auth</div>
                    </div>
                </div>
                <div class="loading-overlay">
                    <div class="spinner"></div>
                    <span>Analyzing email for phishing indicators...</span>
                </div>
            </div>

            <!-- Scan Result -->
            <div id="scan-result-container" style="display:none"></div>
        `;
    },

    mount() {
        this._setupTabs();
        this._setupDropZone();
        this._setupPaste();
    },

    _setupTabs() {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
            });
        });
    },

    _setupDropZone() {
        const zone = document.getElementById('drop-zone');
        const input = document.getElementById('file-input');
        const browseBtn = document.getElementById('browse-btn');

        if (!zone || !input) return;

        browseBtn.addEventListener('click', () => input.click());
        zone.addEventListener('click', () => input.click());

        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            zone.classList.add('drag-over');
        });

        zone.addEventListener('dragleave', () => {
            zone.classList.remove('drag-over');
        });

        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            zone.classList.remove('drag-over');
            const file = e.dataTransfer.files[0];
            if (file) this._handleFileUpload(file);
        });

        input.addEventListener('change', () => {
            if (input.files[0]) this._handleFileUpload(input.files[0]);
        });
    },

    _setupPaste() {
        const btn = document.getElementById('scan-text-btn');
        if (btn) {
            btn.addEventListener('click', () => this._handleTextScan());
        }
    },

    async _handleFileUpload(file) {
        const ext = file.name.toLowerCase().split('.').pop();
        if (!['eml', 'msg'].includes(ext)) {
            App.toast('Please upload a .eml or .msg file', 'error');
            return;
        }

        if (file.size > 25 * 1024 * 1024) {
            App.toast('File is too large (max 25MB)', 'error');
            return;
        }

        this._showProgress();

        try {
            await this._animateSteps();
            const result = await API.scanUpload(file);
            this._scanResult = result;
            this._showResult(result);
        } catch (err) {
            App.toast(`Scan failed: ${err.message}`, 'error');
            this._hideProgress();
        }
    },

    async _handleTextScan() {
        const textarea = document.getElementById('email-text');
        const text = textarea ? textarea.value.trim() : '';

        if (!text) {
            App.toast('Please paste email content first', 'warning');
            return;
        }

        this._showProgress();

        try {
            await this._animateSteps();
            const result = await API.scanText(text);
            this._scanResult = result;
            this._showResult(result);
        } catch (err) {
            App.toast(`Scan failed: ${err.message}`, 'error');
            this._hideProgress();
        }
    },

    _showProgress() {
        const inputCard = document.getElementById('scan-input-card');
        const progressCard = document.getElementById('scan-progress-card');
        const resultContainer = document.getElementById('scan-result-container');

        if (inputCard) inputCard.style.display = 'none';
        if (progressCard) progressCard.style.display = 'block';
        if (resultContainer) resultContainer.style.display = 'none';

        // Reset steps
        document.querySelectorAll('.scan-step').forEach(s => {
            s.classList.remove('active', 'done');
        });
    },

    _hideProgress() {
        document.getElementById('scan-input-card').style.display = 'block';
        document.getElementById('scan-progress-card').style.display = 'none';
    },

    async _animateSteps() {
        const steps = ['parse', 'headers', 'urls', 'content', 'auth'];
        for (let i = 0; i < steps.length; i++) {
            const el = document.querySelector(`.scan-step[data-step="${steps[i]}"]`);
            if (el) {
                el.classList.add('active');
                await new Promise(r => setTimeout(r, 300));
                el.classList.remove('active');
                el.classList.add('done');
                const line = el.querySelector('.scan-step-line');
                if (line) line.classList.add('done');
            }
        }
    },

    _showResult(result) {
        document.getElementById('scan-progress-card').style.display = 'none';
        const container = document.getElementById('scan-result-container');
        container.style.display = 'block';

        const riskColor = this._getRiskColor(result.risk_level);
        const circumference = 2 * Math.PI * 70;
        const offset = circumference - (result.risk_score / 100) * circumference;

        // Group findings by category
        const grouped = { header: [], url: [], content: [], auth: [] };
        (result.findings || []).forEach(f => {
            if (grouped[f.category]) grouped[f.category].push(f);
        });

        container.innerHTML = `
            <div class="scan-result">
                <div class="card">
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
                                    <div class="score-value" style="color:${riskColor}">${result.risk_score}</div>
                                    <div class="score-label">Risk Score</div>
                                </div>
                            </div>
                            <span class="risk-badge ${result.risk_level}">${result.risk_level}</span>
                        </div>
                        <div class="scan-result-meta">
                            <h3>${this._esc(result.subject || '(no subject)')}</h3>
                            <div class="meta-row">
                                <span class="meta-label">From:</span>
                                <span class="meta-value">${this._esc(result.sender_display_name ? `${result.sender_display_name} <${result.sender}>` : result.sender || '—')}</span>
                            </div>
                            <div class="meta-row">
                                <span class="meta-label">To:</span>
                                <span class="meta-value">${this._esc(result.recipient || '—')}</span>
                            </div>
                            <div class="meta-row">
                                <span class="meta-label">Date:</span>
                                <span class="meta-value">${this._esc(result.email_date || '—')}</span>
                            </div>
                            <div class="meta-row">
                                <span class="meta-label">Source:</span>
                                <span class="meta-value">${result.source}</span>
                            </div>
                            ${result.attachment_names && result.attachment_names.length > 0 ? `
                            <div class="meta-row">
                                <span class="meta-label">Files:</span>
                                <span class="meta-value">${result.attachment_names.map(n => this._esc(n)).join(', ')}</span>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                </div>

                <!-- Body Preview -->
                ${result.body_preview ? `
                <div class="card" style="margin-top:var(--space-lg)">
                    <div class="card-header">
                        <span class="card-title">📄 Email Body Preview</span>
                    </div>
                    <div class="body-preview-content">${this._esc(result.body_preview)}</div>
                </div>
                ` : ''}

                <!-- Findings -->
                <div class="card" style="margin-top:var(--space-lg)">
                    <div class="card-header">
                        <span class="card-title">Findings (${result.findings.length})</span>
                    </div>
                    ${this._renderFindingsGroups(grouped)}
                </div>

                ${result.urls_analyzed && result.urls_analyzed.length > 0 ? `
                <div class="card" style="margin-top:var(--space-lg)">
                    <div class="card-header">
                        <span class="card-title">URLs Analyzed (${result.urls_analyzed.length})</span>
                    </div>
                    ${this._renderURLsList(result.urls_analyzed)}
                </div>
                ` : ''}

                <!-- AI Analysis Card -->
                <div class="card ai-analysis-card" style="margin-top:var(--space-lg)" id="ai-analysis-card">
                    <div class="card-header">
                        <span class="card-title">🤖 AI Threat Analysis</span>
                        <button class="btn btn-secondary btn-sm" id="ai-analyze-btn">
                            ✨ Generate Analysis
                        </button>
                    </div>
                    <div id="ai-analysis-content">
                        <p style="color:var(--text-muted);font-size:0.85rem">
                            Click "Generate Analysis" to get an AI-powered plain-English threat summary for this scan.
                        </p>
                    </div>
                </div>

                ${result.raw_headers ? `
                <div style="margin-top:var(--space-lg)">
                    <div class="collapsible-header" id="raw-headers-toggle">
                        <span style="font-weight:600;font-size:0.9rem">📋 Raw Headers</span>
                        <span class="chevron">▼</span>
                    </div>
                    <div class="collapsible-body" id="raw-headers-body">${this._esc(result.raw_headers)}</div>
                </div>
                ` : ''}

                <div style="margin-top:var(--space-xl);display:flex;gap:var(--space-md);flex-wrap:wrap">
                    <button class="btn btn-primary" id="new-scan-btn">🔍 New Scan</button>
                    ${result.id ? `<button class="btn btn-secondary" id="export-report-btn">📥 Export Report</button>` : ''}
                    ${result.id ? `<button class="btn btn-secondary" id="report-issue-btn">📋 Report Issue</button>` : ''}
                </div>
            </div>
        `;

        // Event listeners
        const toggle = document.getElementById('raw-headers-toggle');
        const body = document.getElementById('raw-headers-body');
        if (toggle && body) {
            toggle.addEventListener('click', () => {
                toggle.classList.toggle('open');
                body.classList.toggle('open');
            });
        }

        document.getElementById('new-scan-btn')?.addEventListener('click', () => {
            container.style.display = 'none';
            document.getElementById('scan-input-card').style.display = 'block';
        });

        document.getElementById('export-report-btn')?.addEventListener('click', async () => {
            try {
                await API.exportScan(result.id);
                App.toast('Report downloaded', 'success');
            } catch (err) {
                App.toast(`Export failed: ${err.message}`, 'error');
            }
        });

        // AI Analysis button
        document.getElementById('ai-analyze-btn')?.addEventListener('click', async () => {
            if (!result.id) { App.toast('Scan must be saved to generate AI analysis', 'warning'); return; }
            const contentEl = document.getElementById('ai-analysis-content');
            const btn = document.getElementById('ai-analyze-btn');
            btn.disabled = true;
            btn.textContent = '⏳ Analyzing…';
            contentEl.innerHTML = `<div class="spinner-container"><div class="spinner"></div><span>Generating AI threat summary…</span></div>`;
            try {
                const aiResult = await API.getAiAnalysis(result.id);
                const providerBadge = aiResult.provider && aiResult.provider !== 'none'
                    ? `<span style="font-size:0.7rem;padding:2px 8px;border-radius:9999px;background:rgba(139,92,246,0.15);color:#8b5cf6;margin-left:8px">${aiResult.provider}</span>`
                    : `<span style="font-size:0.7rem;padding:2px 8px;border-radius:9999px;background:rgba(100,120,180,0.1);color:var(--text-muted);margin-left:8px">rule-based</span>`;
                contentEl.innerHTML = `
                    <div class="ai-summary-text">${this._esc(aiResult.summary)}</div>
                    <div style="margin-top:var(--space-sm);display:flex;align-items:center;gap:8px">
                        ${providerBadge}
                        ${aiResult.cached ? '<span style="font-size:0.7rem;color:var(--text-muted)">📦 Cached</span>' : ''}
                    </div>
                `;
                btn.textContent = '↻ Regenerate';
            } catch (err) {
                contentEl.innerHTML = `<p style="color:var(--risk-critical);font-size:0.85rem">Analysis failed: ${this._esc(err.message)}</p>`;
                btn.textContent = '✨ Retry';
            } finally {
                btn.disabled = false;
            }
        });

        // Report Issue button
        document.getElementById('report-issue-btn')?.addEventListener('click', () => {
            this._openReportModal(result.id);
        });
    },

    _openReportModal(scanId) {
        // Show a simple inline report form
        const btn = document.getElementById('report-issue-btn');
        if (!btn) return;

        // Replace button with inline form
        const formHtml = `
            <div class="inline-report-form" id="inline-report-form">
                <div class="card" style="margin-top:var(--space-lg);border-color:rgba(139,92,246,0.3)">
                    <div class="card-header">
                        <span class="card-title">📋 Submit Report for Scan #${scanId}</span>
                        <button class="btn btn-secondary btn-sm" id="report-form-close">✕</button>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Issue Type</label>
                        <select class="form-input" id="inline-report-type">
                            <option value="false_positive">False Positive — This email is safe</option>
                            <option value="missed_threat">Missed Threat — This is phishing but not detected</option>
                            <option value="general">General Feedback</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Comments</label>
                        <textarea class="email-textarea" id="inline-report-comment" style="min-height:80px" placeholder="Describe the issue…"></textarea>
                    </div>
                    <div style="display:flex;gap:var(--space-md)">
                        <button class="btn btn-primary" id="inline-report-submit">Submit Report</button>
                        <button class="btn btn-secondary" id="inline-report-cancel">Cancel</button>
                    </div>
                </div>
            </div>
        `;

        // Insert after action buttons
        const actionsDiv = btn.parentElement;
        const existing = document.getElementById('inline-report-form');
        if (existing) { existing.remove(); return; }

        actionsDiv.insertAdjacentHTML('afterend', formHtml);

        document.getElementById('report-form-close')?.addEventListener('click', () => {
            document.getElementById('inline-report-form')?.remove();
        });
        document.getElementById('inline-report-cancel')?.addEventListener('click', () => {
            document.getElementById('inline-report-form')?.remove();
        });
        document.getElementById('inline-report-submit')?.addEventListener('click', async () => {
            const reportType = document.getElementById('inline-report-type')?.value;
            const comment = document.getElementById('inline-report-comment')?.value;
            const submitBtn = document.getElementById('inline-report-submit');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Submitting…';
            try {
                await API.submitReport({ scanId, reportType, comment });
                App.toast('Report submitted — thank you for the feedback!', 'success');
                document.getElementById('inline-report-form')?.remove();
            } catch (err) {
                App.toast(`Failed: ${err.message}`, 'error');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Submit Report';
            }
        });
    },

    _renderFindingsGroups(grouped) {
        const categoryLabels = {
            header: '📋 Header Analysis',
            url: '🔗 URL Analysis',
            content: '📝 Content Analysis',
            auth: '🔐 Authentication',
        };

        let html = '';
        for (const [cat, findings] of Object.entries(grouped)) {
            if (findings.length === 0) continue;
            html += `
                <div class="findings-group">
                    <div class="findings-group-title">
                        ${categoryLabels[cat] || cat}
                        <span class="findings-group-count">${findings.length}</span>
                    </div>
                    ${findings.map(f => `
                        <div class="finding-card">
                            <div class="severity-dot ${f.severity}" title="${f.severity}"></div>
                            <div class="finding-content">
                                <div class="finding-title">${this._esc(f.title)}</div>
                                <div class="finding-description">${this._esc(f.description)}</div>
                                ${f.evidence ? `<div class="finding-evidence">${this._esc(f.evidence)}</div>` : ''}
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        if (!html) {
            html = `
                <div class="empty-state">
                    <div class="empty-state-icon">✅</div>
                    <div class="empty-state-title">No Issues Found</div>
                    <div class="empty-state-text">This email appears to be legitimate.</div>
                </div>
            `;
        }

        return html;
    },

    _renderURLsList(urls) {
        return urls.map(u => `
            <div class="finding-card" style="border-left:3px solid ${u.is_suspicious ? 'var(--risk-critical)' : 'var(--risk-safe)'}">
                <div class="finding-content">
                    <div class="finding-title" style="font-family:var(--font-mono);font-size:0.82rem;word-break:break-all">
                        ${this._esc(u.url)}
                    </div>
                    ${u.is_suspicious ? `
                        <div class="finding-description" style="color:var(--risk-critical)">
                            ⚠️ ${u.reasons.map(r => this._esc(r)).join(' • ')}
                        </div>
                    ` : `
                        <div class="finding-description" style="color:var(--risk-safe)">✅ No issues detected</div>
                    `}
                </div>
            </div>
        `).join('');
    },

    _getRiskColor(level) {
        const colors = {
            safe: '#22c55e', low: '#84cc16', medium: '#eab308',
            high: '#f97316', critical: '#ef4444',
        };
        return colors[level] || '#94a3b8';
    },

    _esc(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },
};
