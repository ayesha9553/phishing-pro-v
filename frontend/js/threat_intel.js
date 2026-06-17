/**
 * PhishingPro — Threat Intelligence Page
 * URL/IP reputation checking + Domain reputation analysis + User reports
 */

const ThreatIntelPage = {
    _activeTab: 'url-check',

    render() {
        return `
            <div class="page-header">
                <h1 class="page-title">Threat Intelligence</h1>
                <p class="page-subtitle">Check URLs, IPs and domains against VirusTotal, OpenPhish &amp; PhishTank</p>
            </div>

            <!-- Feed Status Bar -->
            <div class="intel-feed-bar" id="intel-feed-bar">
                <span class="feed-loading">Loading feed status…</span>
            </div>

            <div class="tabs" style="margin-bottom:var(--space-lg)">
                <button class="tab-btn active" id="tab-url-check" data-tab="url-check">🔗 URL / IP Check</button>
                <button class="tab-btn" id="tab-domain" data-tab="domain">🌐 Domain Reputation</button>
                <button class="tab-btn" id="tab-reports" data-tab="reports">📋 User Reports</button>
            </div>

            <!-- Tab: URL Check -->
            <div class="tab-content active" id="tab-content-url-check">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">🔗 Multi-Source URL Reputation Check</span>
                    </div>
                    <p style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:var(--space-lg)">
                        Enter a URL or IP address to check it against VirusTotal, OpenPhish, and PhishTank simultaneously.
                    </p>
                    <div class="intel-search-row">
                        <input type="url" class="form-input" id="url-check-input" 
                               placeholder="https://suspicious-site.com/login"
                               style="flex:1;font-family:var(--font-mono);font-size:0.85rem">
                        <button class="btn btn-primary" id="url-check-btn">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
                            Check Now
                        </button>
                    </div>
                    <div id="url-check-result" style="margin-top:var(--space-lg)"></div>
                </div>
            </div>

            <!-- Tab: Domain Reputation -->
            <div class="tab-content" id="tab-content-domain">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">🌐 Domain Reputation Engine</span>
                    </div>
                    <p style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:var(--space-lg)">
                        Analyze a domain's WHOIS data, age, registrar, and SSL certificate validity.
                    </p>
                    <div class="intel-search-row">
                        <input type="text" class="form-input" id="domain-check-input" 
                               placeholder="suspicious-domain.xyz"
                               style="flex:1;font-family:var(--font-mono);font-size:0.85rem">
                        <button class="btn btn-primary" id="domain-check-btn">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                            Analyze Domain
                        </button>
                    </div>
                    <div id="domain-check-result" style="margin-top:var(--space-lg)"></div>
                </div>
            </div>

            <!-- Tab: User Reports -->
            <div class="tab-content" id="tab-content-reports">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">📋 User-Submitted Reports</span>
                        <button class="btn btn-primary btn-sm" id="new-report-btn">+ New Report</button>
                    </div>
                    <div id="reports-list">
                        <div class="spinner-container"><div class="spinner"></div></div>
                    </div>
                </div>
            </div>

            <!-- Report Modal -->
            <div class="modal-overlay" id="report-modal" style="display:none">
                <div class="modal-box">
                    <div class="modal-header">
                        <h3 class="modal-title">Submit Threat Report</h3>
                        <button class="modal-close" id="report-modal-close">×</button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">Report Type</label>
                            <select class="form-input" id="report-type-select">
                                <option value="false_positive">False Positive — Safe email flagged as threat</option>
                                <option value="missed_threat">Missed Threat — Phishing email not detected</option>
                                <option value="general">General Feedback</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Scan ID (optional)</label>
                            <input type="number" class="form-input" id="report-scan-id" placeholder="e.g. 42">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Your Email (optional)</label>
                            <input type="email" class="form-input" id="report-email" placeholder="analyst@company.com">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Comments</label>
                            <textarea class="email-textarea" id="report-comment" style="min-height:100px" 
                                      placeholder="Describe the issue in detail…"></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" id="report-cancel-btn">Cancel</button>
                        <button class="btn btn-primary" id="report-submit-btn">Submit Report</button>
                    </div>
                </div>
            </div>
        `;
    },

    async mount() {
        this._setupTabs();
        this._setupUrlCheck();
        this._setupDomainCheck();
        this._setupReportModal();
        this._loadFeedStatus();
        await this._loadReports();
    },

    _setupTabs() {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const tab = btn.dataset.tab;
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById(`tab-content-${tab}`)?.classList.add('active');
                this._activeTab = tab;
                if (tab === 'reports') this._loadReports();
            });
        });
    },

    async _loadFeedStatus() {
        const bar = document.getElementById('intel-feed-bar');
        if (!bar) return;
        try {
            const status = await API.getFeedStatus();
            const op = status.openphish;
            const pt = status.phishtank;
            const vt = status.virustotal;

            bar.innerHTML = `
                <span class="feed-status-item ${op.status === 'ok' ? 'ok' : 'warn'}">
                    <span class="feed-dot"></span>
                    OpenPhish: ${op.feed_size ? op.feed_size.toLocaleString() + ' URLs' : 'Loading…'}
                    ${op.last_updated_hours_ago !== null ? `(${op.last_updated_hours_ago}h ago)` : ''}
                </span>
                <span class="feed-status-item ${vt.configured ? 'ok' : 'warn'}">
                    <span class="feed-dot"></span>
                    VirusTotal: ${vt.configured ? 'Configured' : 'Not configured'}
                </span>
                <span class="feed-status-item ok">
                    <span class="feed-dot"></span>
                    PhishTank: Active
                </span>
            `;
        } catch (e) {
            bar.innerHTML = `<span class="feed-status-item warn">Feed status unavailable</span>`;
        }
    },

    _setupUrlCheck() {
        const btn = document.getElementById('url-check-btn');
        const input = document.getElementById('url-check-input');
        if (!btn || !input) return;

        const doCheck = async () => {
            const url = input.value.trim();
            if (!url) { App.toast('Enter a URL to check', 'warning'); return; }

            const resultEl = document.getElementById('url-check-result');
            resultEl.innerHTML = `<div class="spinner-container"><div class="spinner"></div><span>Checking against all sources…</span></div>`;

            try {
                const data = await API.checkUrlIntel(url);
                this._renderUrlCheckResult(data, resultEl);
            } catch (err) {
                resultEl.innerHTML = `<div class="alert-card error">❌ Check failed: ${this._esc(err.message)}</div>`;
            }
        };

        btn.addEventListener('click', doCheck);
        input.addEventListener('keydown', e => { if (e.key === 'Enter') doCheck(); });
    },

    _renderUrlCheckResult(data, container) {
        const overall = data.overall_malicious;
        const sources = data.sources || {};

        container.innerHTML = `
            <div class="intel-result-header ${overall ? 'malicious' : 'safe'}">
                <div class="intel-result-verdict">
                    ${overall ? '🚨 MALICIOUS' : '✅ CLEAN'}
                </div>
                <div class="intel-result-url">${this._esc(data.url)}</div>
            </div>
            <div class="intel-sources-grid">
                ${Object.entries(sources).map(([source, result]) => this._renderSourceCard(source, result)).join('')}
            </div>
        `;
    },

    _renderSourceCard(source, result) {
        const isError = !!result.error;
        const isMalicious = result.is_malicious;
        const isDisabled = result.enabled === false;

        const sourceNames = { virustotal: 'VirusTotal', openphish: 'OpenPhish', phishtank: 'PhishTank' };
        const name = sourceNames[source] || source;

        if (isDisabled) {
            return `
                <div class="intel-source-card disabled">
                    <div class="intel-source-header">
                        <span class="intel-source-name">${name}</span>
                        <span class="intel-source-badge na">Not configured</span>
                    </div>
                    <p style="font-size:0.8rem;color:var(--text-muted)">${result.message || 'Configure API key in Settings'}</p>
                </div>
            `;
        }

        if (isError) {
            return `
                <div class="intel-source-card warning">
                    <div class="intel-source-header">
                        <span class="intel-source-name">${name}</span>
                        <span class="intel-source-badge warn">Error</span>
                    </div>
                    <p style="font-size:0.8rem;color:var(--text-muted)">${this._esc(result.error)}</p>
                </div>
            `;
        }

        let details = '';
        if (source === 'virustotal' && !isError) {
            details = `<p style="font-size:0.8rem;color:var(--text-secondary)">${result.malicious_count || 0} malicious / ${result.suspicious_count || 0} suspicious out of ${result.total_vendors || 0} vendors</p>`;
            if (result.permalink) details += `<a href="${result.permalink}" target="_blank" style="font-size:0.75rem">View on VirusTotal →</a>`;
        } else if (source === 'openphish') {
            details = `<p style="font-size:0.8rem;color:var(--text-secondary)">Feed: ${(result.feed_size || 0).toLocaleString()} known phishing URLs${result.matched ? `<br>Matched: ${this._esc(result.matched)}` : ''}</p>`;
        } else if (source === 'phishtank') {
            details = `<p style="font-size:0.8rem;color:var(--text-secondary)">${result.in_database ? `In PhishTank DB${result.verified ? ' (Verified)' : ' (Unverified)'}` : 'Not in PhishTank database'}${result.phish_detail_url ? `<br><a href="${result.phish_detail_url}" target="_blank" style="font-size:0.75rem">View on PhishTank →</a>` : ''}</p>`;
        }

        return `
            <div class="intel-source-card ${isMalicious ? 'malicious' : 'clean'}">
                <div class="intel-source-header">
                    <span class="intel-source-name">${name}</span>
                    <span class="intel-source-badge ${isMalicious ? 'danger' : 'safe'}">${isMalicious ? 'MALICIOUS' : 'CLEAN'}</span>
                </div>
                ${details}
                ${result.cached ? '<span style="font-size:0.7rem;color:var(--text-muted);margin-top:4px;display:block">📦 Cached result</span>' : ''}
            </div>
        `;
    },

    _setupDomainCheck() {
        const btn = document.getElementById('domain-check-btn');
        const input = document.getElementById('domain-check-input');
        if (!btn || !input) return;

        const doCheck = async () => {
            const domain = input.value.trim();
            if (!domain) { App.toast('Enter a domain to analyze', 'warning'); return; }

            const resultEl = document.getElementById('domain-check-result');
            resultEl.innerHTML = `<div class="spinner-container"><div class="spinner"></div><span>Analyzing domain…</span></div>`;

            try {
                const data = await API.checkDomainReputation(domain);
                this._renderDomainResult(data, resultEl);
            } catch (err) {
                resultEl.innerHTML = `<div class="alert-card error">❌ Analysis failed: ${this._esc(err.message)}</div>`;
            }
        };

        btn.addEventListener('click', doCheck);
        input.addEventListener('keydown', e => { if (e.key === 'Enter') doCheck(); });
    },

    _renderDomainResult(data, container) {
        if (data.error) {
            container.innerHTML = `<div class="alert-card error">❌ ${this._esc(data.error)}</div>`;
            return;
        }

        const score = data.reputation_score || 0;
        const level = data.risk_level || 'safe';
        const levelColors = { safe: '#22c55e', low: '#84cc16', medium: '#eab308', high: '#ef4444' };
        const color = levelColors[level] || '#94a3b8';

        const ageDisplay = data.domain_age_days !== null && data.domain_age_days !== undefined
            ? (data.domain_age_days < 30 ? `⚠️ ${data.domain_age_days} days (very new!)` :
               data.domain_age_days < 365 ? `${data.domain_age_days} days` :
               `${Math.floor(data.domain_age_days / 365)} years, ${data.domain_age_days % 365} days`)
            : '—';

        const sslDays = data.ssl_days_remaining;
        const sslDisplay = data.ssl_valid
            ? (sslDays !== null ? `Valid — expires in ${sslDays} days` : 'Valid')
            : (data.ssl_issuer === null && !data.details?.ssl?.error ? 'Not checked' : '⚠️ Invalid or missing');

        const flags = data.risk_flags || [];

        container.innerHTML = `
            <div class="domain-result-grid">
                <!-- Score Card -->
                <div class="domain-score-card">
                    <div class="domain-score-ring" style="--score:${score};--color:${color}">
                        <svg viewBox="0 0 100 100" width="120" height="120">
                            <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(100,120,180,0.1)" stroke-width="8"/>
                            <circle cx="50" cy="50" r="40" fill="none" stroke="${color}" stroke-width="8"
                                stroke-dasharray="${(score / 100) * 251.3} 251.3"
                                stroke-dashoffset="62.8" stroke-linecap="round"/>
                        </svg>
                        <div class="domain-score-text">
                            <span class="domain-score-val" style="color:${color}">${Math.round(score)}</span>
                            <span class="domain-score-label">Risk</span>
                        </div>
                    </div>
                    <div class="domain-name">${this._esc(data.domain)}</div>
                    <span class="risk-badge ${level}">${level} risk</span>
                    ${data.cached ? '<span style="font-size:0.7rem;color:var(--text-muted);margin-top:4px">📦 Cached 24h</span>' : ''}
                </div>

                <!-- Details Card -->
                <div class="domain-details-card">
                    <div class="domain-detail-grid">
                        <div class="domain-detail-item">
                            <span class="domain-detail-label">Domain Age</span>
                            <span class="domain-detail-value">${ageDisplay}</span>
                        </div>
                        <div class="domain-detail-item">
                            <span class="domain-detail-label">Registrar</span>
                            <span class="domain-detail-value">${this._esc(data.whois_registrar || '—')}</span>
                        </div>
                        <div class="domain-detail-item">
                            <span class="domain-detail-label">SSL Certificate</span>
                            <span class="domain-detail-value">${sslDisplay}</span>
                        </div>
                        <div class="domain-detail-item">
                            <span class="domain-detail-label">SSL Issuer</span>
                            <span class="domain-detail-value">${this._esc(data.ssl_issuer || '—')}</span>
                        </div>
                        <div class="domain-detail-item">
                            <span class="domain-detail-label">Registration Date</span>
                            <span class="domain-detail-value">${data.creation_date ? data.creation_date.split('T')[0] : '—'}</span>
                        </div>
                        <div class="domain-detail-item">
                            <span class="domain-detail-label">SSL Expires</span>
                            <span class="domain-detail-value">${data.ssl_expires || '—'}</span>
                        </div>
                    </div>

                    ${flags.length ? `
                        <div class="domain-flags">
                            <div class="domain-flags-title">⚠️ Risk Factors</div>
                            ${flags.map(f => `<div class="domain-flag-item">• ${this._esc(f)}</div>`).join('')}
                        </div>
                    ` : `<div class="domain-flags safe">✅ No risk factors detected</div>`}
                </div>
            </div>
        `;
    },

    _setupReportModal() {
        const modal = document.getElementById('report-modal');
        const newBtn = document.getElementById('new-report-btn');
        const closeBtn = document.getElementById('report-modal-close');
        const cancelBtn = document.getElementById('report-cancel-btn');
        const submitBtn = document.getElementById('report-submit-btn');

        const open = () => { if (modal) modal.style.display = 'flex'; };
        const close = () => { if (modal) modal.style.display = 'none'; };

        newBtn?.addEventListener('click', open);
        closeBtn?.addEventListener('click', close);
        cancelBtn?.addEventListener('click', close);
        modal?.addEventListener('click', e => { if (e.target === modal) close(); });

        submitBtn?.addEventListener('click', async () => {
            const scanId = document.getElementById('report-scan-id')?.value;
            const reportType = document.getElementById('report-type-select')?.value;
            const email = document.getElementById('report-email')?.value;
            const comment = document.getElementById('report-comment')?.value;

            try {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Submitting…';
                await API.submitReport({
                    scanId: scanId ? parseInt(scanId) : null,
                    reporterEmail: email,
                    reportType,
                    comment,
                });
                App.toast('Report submitted successfully', 'success');
                close();
                await this._loadReports();
            } catch (err) {
                App.toast(`Submit failed: ${err.message}`, 'error');
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Submit Report';
            }
        });
    },

    async _loadReports() {
        const el = document.getElementById('reports-list');
        if (!el) return;
        try {
            const data = await API.getUserReports(100);
            const reports = data.reports || [];

            if (!reports.length) {
                el.innerHTML = `<div class="empty-state" style="padding:var(--space-xl)">
                    <div class="empty-state-icon">📋</div>
                    <div class="empty-state-title">No reports yet</div>
                    <div class="empty-state-text">Use the "+ New Report" button to submit feedback about scan accuracy.</div>
                </div>`;
                return;
            }

            el.innerHTML = `<table class="data-table">
                <thead>
                    <tr><th>Type</th><th>Comment</th><th>Scan</th><th>Reporter</th><th>Date</th></tr>
                </thead>
                <tbody>
                    ${reports.map(r => {
                        const typeColor = { false_positive: '#22c55e', missed_threat: '#ef4444', general: '#94a3b8' };
                        const typeName = { false_positive: 'False Positive', missed_threat: 'Missed Threat', general: 'General' };
                        const color = typeColor[r.report_type] || '#94a3b8';
                        return `<tr>
                            <td><span style="color:${color};font-size:0.8rem;font-weight:600">${typeName[r.report_type] || r.report_type}</span></td>
                            <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${this._esc(r.comment || '—')}</td>
                            <td>${r.scan_id ? `<a href="#/history/${r.scan_id}" style="font-family:var(--font-mono)">#${r.scan_id}</a>` : '—'}</td>
                            <td style="font-size:0.8rem;color:var(--text-secondary)">${this._esc(r.reporter_email || 'Anonymous')}</td>
                            <td class="cell-date">${this._formatDate(r.created_at)}</td>
                        </tr>`;
                    }).join('')}
                </tbody>
            </table>`;
        } catch (err) {
            el.innerHTML = `<div class="alert-card error">Failed to load reports: ${err.message}</div>`;
        }
    },

    _esc(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    },

    _formatDate(dateStr) {
        if (!dateStr) return '—';
        try {
            return new Date(dateStr).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        } catch { return dateStr; }
    },
};
