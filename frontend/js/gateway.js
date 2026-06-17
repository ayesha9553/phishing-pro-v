/**
 * PhishingPro — Email Gateway Page
 * Real-time email gateway management and monitoring.
 */

const GatewayPage = {
    _config: null,

    render() {
        return `
            <div class="page-header" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:var(--space-md)">
                <div>
                    <h1 class="page-title">Email Gateway</h1>
                    <p class="page-subtitle">Real-time pre-delivery email scanning — scan emails before they reach users</p>
                </div>
                <button class="btn btn-secondary btn-sm" id="gateway-refresh-btn">↻ Refresh</button>
            </div>

            <!-- Gateway Stats -->
            <div class="stats-grid" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr));margin-bottom:var(--space-lg)">
                <div class="card stat-card stat-safe">
                    <div class="stat-icon">✅</div>
                    <div class="stat-value" id="gw-stat-allowed">—</div>
                    <div class="stat-label">Emails Allowed</div>
                </div>
                <div class="card stat-card stat-threats">
                    <div class="stat-icon">⚠️</div>
                    <div class="stat-value" id="gw-stat-quarantined" style="color:#f97316">—</div>
                    <div class="stat-label">Quarantined</div>
                </div>
                <div class="card stat-card">
                    <div class="stat-icon" style="background:rgba(239,68,68,0.15);color:#ef4444">🚫</div>
                    <div class="stat-value" id="gw-stat-blocked" style="color:#ef4444">—</div>
                    <div class="stat-label">Blocked</div>
                </div>
                <div class="card stat-card stat-total">
                    <div class="stat-icon">📨</div>
                    <div class="stat-value" id="gw-stat-total">—</div>
                    <div class="stat-label">Total Processed</div>
                </div>
            </div>

            <div class="dashboard-grid" style="margin-bottom:var(--space-lg)">
                <!-- Configuration Panel -->
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">⚙️ Gateway Configuration</span>
                    </div>

                    <div class="gateway-config-section">
                        <div class="gateway-threshold-group">
                            <label class="form-label">Quarantine Threshold
                                <span class="threshold-hint" id="quarantine-val">60</span>/100
                            </label>
                            <input type="range" class="threshold-slider" id="quarantine-slider"
                                   min="0" max="100" value="60" step="5">
                            <p style="font-size:0.75rem;color:var(--text-muted)">Emails scoring ≥ this are quarantined for review</p>
                        </div>

                        <div class="gateway-threshold-group" style="margin-top:var(--space-lg)">
                            <label class="form-label">Block Threshold
                                <span class="threshold-hint danger" id="block-val">85</span>/100
                            </label>
                            <input type="range" class="threshold-slider danger" id="block-slider"
                                   min="0" max="100" value="85" step="5">
                            <p style="font-size:0.75rem;color:var(--text-muted)">Emails scoring ≥ this are blocked outright</p>
                        </div>

                        <div class="gateway-action-bar">
                            <button class="btn btn-primary" id="gateway-save-config-btn">Save Configuration</button>
                        </div>
                    </div>

                    <div style="margin-top:var(--space-lg);padding-top:var(--space-lg);border-top:1px solid var(--glass-border)">
                        <div class="card-header" style="margin-bottom:var(--space-md)">
                            <span class="card-title">🔌 Integration Guide</span>
                        </div>
                        <div class="integration-tabs">
                            <button class="integration-tab active" data-target="postfix">Postfix</button>
                            <button class="integration-tab" data-target="webhook">Webhook</button>
                            <button class="integration-tab" data-target="curl">cURL Test</button>
                        </div>
                        <div class="integration-code" id="integration-postfix">
<pre><code># /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:8025

# Or use content_filter for simpler setup:
# content_filter = scan:[127.0.0.1]:8025

# Then in master.cf, add a transport that POSTs
# to PhishingPro gateway endpoint:</code></pre>
                        </div>
                        <div class="integration-code" id="integration-webhook" style="display:none">
<pre><code># POST raw email to the gateway endpoint:
POST /api/gateway/ingest
Content-Type: application/json

{
  "raw_email": "&lt;RFC 822 raw email content&gt;",
  "source_ip": "203.0.113.1",
  "envelope_from": "sender@domain.com",
  "envelope_to": "user@yourcompany.com"
}</code></pre>
                        </div>
                        <div class="integration-code" id="integration-curl" style="display:none">
<pre><code># Test the gateway with a sample email:
curl -X POST http://localhost:8000/api/gateway/ingest \\
  -H "Content-Type: application/json" \\
  -d '{
    "raw_email": "From: test@example.com\\nTo: you@company.com\\nSubject: Test\\n\\nHello",
    "envelope_from": "test@example.com",
    "envelope_to": "you@company.com"
  }'</code></pre>
                        </div>
                    </div>
                </div>

                <!-- IMAP Polling Status -->
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">📬 IMAP Polling</span>
                        <span class="status-badge" id="imap-status-badge">Checking…</span>
                    </div>
                    <div id="imap-config-panel">
                        <div class="spinner-container"><div class="spinner"></div></div>
                    </div>

                    <!-- Manual Test Panel -->
                    <div style="margin-top:var(--space-lg);padding-top:var(--space-lg);border-top:1px solid var(--glass-border)">
                        <div class="card-title" style="margin-bottom:var(--space-md)">🧪 Manual Email Test</div>
                        <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:var(--space-md)">
                            Paste a raw email below to test the gateway pipeline directly.
                        </p>
                        <textarea class="email-textarea" id="gateway-test-email" style="min-height:120px"
                                  placeholder="From: attacker@evil.com&#10;To: victim@company.com&#10;Subject: Urgent: Verify your account&#10;&#10;Click here: http://evil.com/login"></textarea>
                        <button class="btn btn-primary" id="gateway-test-btn" style="margin-top:var(--space-md)">
                            🛡️ Test Gateway Scan
                        </button>
                        <div id="gateway-test-result" style="margin-top:var(--space-md)"></div>
                    </div>
                </div>
            </div>

            <!-- Gateway Log Table -->
            <div class="card">
                <div class="card-header">
                    <span class="card-title">📋 Gateway Processing Log</span>
                    <button class="btn btn-secondary btn-sm" id="gateway-refresh-log-btn">↻ Refresh</button>
                </div>
                <div id="gateway-log-table">
                    <div class="spinner-container"><div class="spinner"></div></div>
                </div>
            </div>
        `;
    },

    async mount() {
        document.getElementById('gateway-refresh-btn')?.addEventListener('click', () => this._loadAll());
        document.getElementById('gateway-refresh-log-btn')?.addEventListener('click', () => this._loadLogs());
        this._setupThresholdSliders();
        this._setupIntegrationTabs();
        this._setupTestPanel();
        await this._loadAll();
    },

    async _loadAll() {
        await Promise.all([this._loadStats(), this._loadConfig(), this._loadLogs()]);
    },

    async _loadStats() {
        try {
            const stats = await API.getGatewayStats();
            const setCount = (id, val) => {
                const el = document.getElementById(id);
                if (el) el.textContent = val ?? '0';
            };
            setCount('gw-stat-allowed', stats.allowed);
            setCount('gw-stat-quarantined', stats.quarantined);
            setCount('gw-stat-blocked', stats.blocked);
            setCount('gw-stat-total', stats.total_processed);
        } catch (err) {
            console.error('Gateway stats load failed:', err);
        }
    },

    async _loadConfig() {
        try {
            const config = await API.getGatewayConfig();
            this._config = config;
            const t = config.thresholds;

            const qSlider = document.getElementById('quarantine-slider');
            const bSlider = document.getElementById('block-slider');
            const qVal = document.getElementById('quarantine-val');
            const bVal = document.getElementById('block-val');

            if (qSlider) { qSlider.value = t.quarantine; }
            if (bSlider) { bSlider.value = t.block; }
            if (qVal) qVal.textContent = t.quarantine;
            if (bVal) bVal.textContent = t.block;

            const imap = config.imap_polling;
            const badge = document.getElementById('imap-status-badge');
            const panel = document.getElementById('imap-config-panel');

            if (badge) {
                badge.className = `status-badge ${imap.enabled ? 'connected' : 'disconnected'}`;
                badge.textContent = imap.enabled ? 'Active' : 'Disabled';
            }

            if (panel) {
                if (imap.enabled) {
                    panel.innerHTML = `
                        <div class="imap-info">
                            <div class="imap-info-row">
                                <span class="imap-label">Host</span>
                                <span class="imap-value">${this._esc(imap.host)}</span>
                            </div>
                            <div class="imap-info-row">
                                <span class="imap-label">Folder</span>
                                <span class="imap-value">${this._esc(imap.folder)}</span>
                            </div>
                            <div class="imap-info-row">
                                <span class="imap-label">Poll Interval</span>
                                <span class="imap-value">${imap.interval_seconds}s</span>
                            </div>
                        </div>
                    `;
                } else {
                    panel.innerHTML = `
                        <div class="empty-mini">
                            IMAP polling is not configured.
                        </div>
                        <p style="font-size:0.8rem;color:var(--text-muted);margin-top:var(--space-sm)">
                            Set <code>IMAP_HOST</code>, <code>IMAP_USER</code>, <code>IMAP_PASS</code> in your <code>.env</code> file to enable automatic inbox polling.
                        </p>
                    `;
                }
            }
        } catch (err) {
            console.error('Gateway config load failed:', err);
        }
    },

    async _loadLogs() {
        const el = document.getElementById('gateway-log-table');
        if (!el) return;
        try {
            const data = await API.getGatewayLogs(100);
            const logs = data.logs || [];

            if (!logs.length) {
                el.innerHTML = `<div class="empty-state" style="padding:var(--space-xl)">
                    <div class="empty-state-icon">📨</div>
                    <div class="empty-state-title">No emails processed yet</div>
                    <div class="empty-state-text">Configure your mail server to send emails to the gateway endpoint, or use the manual test panel above.</div>
                </div>`;
                return;
            }

            el.innerHTML = `<table class="data-table">
                <thead>
                    <tr>
                        <th>Action</th>
                        <th>From</th>
                        <th>To</th>
                        <th>Subject</th>
                        <th>Risk</th>
                        <th>Score</th>
                        <th>Source IP</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    ${logs.map(log => {
                        const actionColor = { allowed: '#22c55e', quarantined: '#f97316', blocked: '#ef4444' };
                        const actionIcon = { allowed: '✅', quarantined: '⚠️', blocked: '🚫' };
                        const color = actionColor[log.action_taken] || '#94a3b8';
                        const icon = actionIcon[log.action_taken] || '?';
                        return `<tr ${log.scan_id ? `style="cursor:pointer" onclick="location.hash='#/history/${log.scan_id}'"` : ''}>
                            <td><span style="color:${color};font-weight:600;font-size:0.8rem">${icon} ${(log.action_taken || '').toUpperCase()}</span></td>
                            <td class="cell-sender">${this._esc(log.envelope_from || '—')}</td>
                            <td style="font-size:0.8rem;color:var(--text-secondary)">${this._esc(log.envelope_to || '—')}</td>
                            <td class="cell-subject">${this._esc(log.subject || '—')}</td>
                            <td><span class="risk-badge ${log.risk_level}">${log.risk_level}</span></td>
                            <td class="cell-score">${(log.risk_score || 0).toFixed(1)}</td>
                            <td style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted)">${this._esc(log.source_ip || '—')}</td>
                            <td class="cell-date">${this._formatDate(log.created_at)}</td>
                        </tr>`;
                    }).join('')}
                </tbody>
            </table>`;
        } catch (err) {
            el.innerHTML = `<div class="alert-card error">Failed to load logs: ${err.message}</div>`;
        }
    },

    _setupThresholdSliders() {
        const qSlider = document.getElementById('quarantine-slider');
        const bSlider = document.getElementById('block-slider');
        const qVal = document.getElementById('quarantine-val');
        const bVal = document.getElementById('block-val');

        qSlider?.addEventListener('input', () => { if (qVal) qVal.textContent = qSlider.value; });
        bSlider?.addEventListener('input', () => { if (bVal) bVal.textContent = bSlider.value; });

        document.getElementById('gateway-save-config-btn')?.addEventListener('click', async () => {
            const q = parseInt(qSlider?.value || 60);
            const b = parseInt(bSlider?.value || 85);

            if (q >= b) {
                App.toast('Quarantine threshold must be lower than block threshold', 'warning');
                return;
            }

            try {
                await API.updateGatewayConfig({ quarantineThreshold: q, blockThreshold: b });
                App.toast('Gateway configuration saved', 'success');
            } catch (err) {
                App.toast(`Save failed: ${err.message}`, 'error');
            }
        });
    },

    _setupIntegrationTabs() {
        document.querySelectorAll('.integration-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.integration-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.integration-code').forEach(c => c.style.display = 'none');
                tab.classList.add('active');
                document.getElementById(`integration-${tab.dataset.target}`)?.style.setProperty('display', 'block');
            });
        });
    },

    _setupTestPanel() {
        const btn = document.getElementById('gateway-test-btn');
        if (!btn) return;

        btn.addEventListener('click', async () => {
            const rawEmail = document.getElementById('gateway-test-email')?.value.trim();
            if (!rawEmail) { App.toast('Paste a raw email to test', 'warning'); return; }

            const resultEl = document.getElementById('gateway-test-result');
            resultEl.innerHTML = `<div class="spinner-container"><div class="spinner"></div><span>Processing email through gateway…</span></div>`;
            btn.disabled = true;

            try {
                const result = await API.ingestEmail({ rawEmail, envelopeFrom: '', envelopeTo: '' });
                const actionColor = { allowed: '#22c55e', quarantined: '#f97316', blocked: '#ef4444' };
                const actionIcon = { allowed: '✅', quarantined: '⚠️', blocked: '🚫' };
                const color = actionColor[result.action] || '#94a3b8';

                resultEl.innerHTML = `
                    <div class="gateway-test-result-card" style="border-color:${color}40">
                        <div class="gateway-test-action" style="color:${color}">
                            ${actionIcon[result.action] || '?'} Action: <strong>${(result.action || '').toUpperCase()}</strong>
                        </div>
                        <div class="gateway-test-details">
                            <span>Risk Score: <strong>${result.risk_score?.toFixed(1)}</strong></span>
                            <span>Level: <span class="risk-badge ${result.risk_level}">${result.risk_level}</span></span>
                            <span>Findings: <strong>${result.findings_count || 0}</strong></span>
                            ${result.scan_id ? `<a href="#/history/${result.scan_id}" class="btn btn-secondary btn-sm">View Full Report</a>` : ''}
                        </div>
                        <div class="gateway-threshold-info">
                            Thresholds: Quarantine ≥ ${result.thresholds?.quarantine} · Block ≥ ${result.thresholds?.block}
                        </div>
                    </div>
                `;
                await this._loadLogs();
            } catch (err) {
                resultEl.innerHTML = `<div class="alert-card error">❌ Gateway error: ${this._esc(err.message)}</div>`;
            } finally {
                btn.disabled = false;
            }
        });
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
