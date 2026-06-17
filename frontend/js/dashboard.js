/**
 * PhishingPro — Enhanced SOC Dashboard
 * Full Security Operations Center view with advanced analytics.
 */

const DashboardPage = {
    _charts: {},
    _stats: null,

    render() {
        return `
            <div class="page-header" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:var(--space-md)">
                <div>
                    <h1 class="page-title">SOC Dashboard</h1>
                    <p class="page-subtitle">Security Operations Center — Real-time threat intelligence overview</p>
                </div>
                <div style="display:flex;gap:var(--space-sm);align-items:center">
                    <span class="live-indicator" id="live-indicator">
                        <span class="pulse-dot"></span> Live
                    </span>
                    <button class="btn btn-secondary btn-sm" id="refresh-dashboard-btn">↻ Refresh</button>
                </div>
            </div>

            <!-- KPI Cards -->
            <div class="stats-grid" id="stats-grid">
                <div class="card stat-card stat-total">
                    <div class="stat-icon">📊</div>
                    <div class="stat-value" id="stat-total">—</div>
                    <div class="stat-label">Total Scans</div>
                    <div class="stat-delta" id="stat-total-delta"></div>
                </div>
                <div class="card stat-card stat-threats">
                    <div class="stat-icon">🚨</div>
                    <div class="stat-value" id="stat-threats">—</div>
                    <div class="stat-label">Threats Detected</div>
                </div>
                <div class="card stat-card stat-safe">
                    <div class="stat-icon">✅</div>
                    <div class="stat-value" id="stat-safe">—</div>
                    <div class="stat-label">Safe Emails</div>
                </div>
                <div class="card stat-card stat-score">
                    <div class="stat-icon">📈</div>
                    <div class="stat-value" id="stat-avgscore">—</div>
                    <div class="stat-label">Avg Risk Score</div>
                </div>
                <div class="card stat-card" style="--stat-color:#f59e0b">
                    <div class="stat-icon" style="background:rgba(245,158,11,0.15);color:#f59e0b">📋</div>
                    <div class="stat-value" id="stat-reports" style="color:#f59e0b">—</div>
                    <div class="stat-label">User Reports</div>
                </div>
                <div class="card stat-card" style="--stat-color:#a78bfa">
                    <div class="stat-icon" style="background:rgba(167,139,250,0.15);color:#a78bfa">🛡️</div>
                    <div class="stat-value" id="stat-gateway" style="color:#a78bfa">—</div>
                    <div class="stat-label">Gateway Processed</div>
                </div>
            </div>

            <!-- Row 1: 30-day trend + Risk distribution -->
            <div class="dashboard-grid" style="margin-bottom:var(--space-lg)">
                <div class="card" style="grid-column:span 2">
                    <div class="card-header">
                        <span class="card-title">📈 30-Day Phishing Trend</span>
                        <div style="display:flex;gap:var(--space-sm)">
                            <span class="legend-item" style="color:#06b6d4">■ Scans</span>
                            <span class="legend-item" style="color:#ef4444">■ Threats</span>
                            <span class="legend-item" style="color:#8b5cf6">— Avg Score</span>
                        </div>
                    </div>
                    <div class="chart-container" id="trend-chart-container" style="height:220px">
                        <canvas id="trend-chart"></canvas>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <span class="card-title">🍩 Risk Distribution</span>
                    </div>
                    <div class="chart-container" id="risk-chart-container">
                        <canvas id="risk-chart"></canvas>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <span class="card-title">🎯 Threat Category Breakdown</span>
                    </div>
                    <div class="chart-container" id="category-chart-container">
                        <canvas id="category-chart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Row 2: Attack Sources + Score Distribution -->
            <div class="dashboard-grid" style="margin-bottom:var(--space-lg)">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">⚔️ Top Attack Sources</span>
                        <span class="card-badge" id="attack-sources-count">—</span>
                    </div>
                    <div id="attack-sources-list"></div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <span class="card-title">📊 Risk Score Distribution</span>
                    </div>
                    <div class="chart-container" id="score-dist-container">
                        <canvas id="score-dist-chart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Row 3: Gateway stats + Recent Scans -->
            <div class="dashboard-grid" style="margin-bottom:var(--space-lg)">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">🛡️ Gateway Activity</span>
                    </div>
                    <div id="gateway-stats-panel"></div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <span class="card-title">📋 User Reports</span>
                        <a href="#/threat-intel" class="btn btn-secondary btn-sm">View All</a>
                    </div>
                    <div id="user-reports-panel"></div>
                </div>
            </div>

            <!-- Row 4: Full-width recent scans -->
            <div class="card" style="margin-bottom:var(--space-lg)">
                <div class="card-header">
                    <span class="card-title">🕐 Recent Scans</span>
                    <a href="#/scan" class="btn btn-primary btn-sm">+ New Scan</a>
                </div>
                <div id="recent-scans-table"></div>
            </div>
        `;
    },

    async mount() {
        document.getElementById('refresh-dashboard-btn')?.addEventListener('click', () => this._loadData());
        await this._loadData();
    },

    async _loadData() {
        try {
            const stats = await API.getStats();
            this._stats = stats;
            this._updateKPIs(stats);
            this._renderTrendChart(stats.daily_trend_30 || stats.daily_trend || []);
            this._renderRiskChart(stats.risk_breakdown || {});
            this._renderCategoryChart(stats.category_breakdown || {});
            this._renderAttackSources(stats.attack_sources || []);
            this._renderScoreDistribution(stats.score_distribution || {});
            this._renderGatewayStats(stats.gateway_stats || {});
            this._renderUserReportsPanel(stats.user_reports_count || 0, stats.reports_by_type || {});
            this._renderRecentScans(stats.recent_scans || []);
        } catch (err) {
            this._showEmptyDashboard();
        }
    },

    _updateKPIs(stats) {
        this._animateCount('stat-total', stats.total_scans);
        this._animateCount('stat-threats', stats.threats_detected);
        this._animateCount('stat-safe', stats.safe_emails);
        const scoreEl = document.getElementById('stat-avgscore');
        if (scoreEl) scoreEl.textContent = (stats.avg_risk_score || 0).toFixed(1);
        this._animateCount('stat-reports', stats.user_reports_count || 0);
        const gatewayTotal = Object.values(stats.gateway_stats || {}).reduce((a, b) => a + b, 0);
        this._animateCount('stat-gateway', gatewayTotal);
    },

    _animateCount(id, target) {
        const el = document.getElementById(id);
        if (!el) return;
        let current = 0;
        const step = Math.max(1, Math.ceil(target / 30));
        const interval = setInterval(() => {
            current += step;
            if (current >= target) { current = target; clearInterval(interval); }
            el.textContent = current;
        }, 30);
    },

    _renderTrendChart(trend) {
        const canvas = document.getElementById('trend-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);
        canvas.style.width = rect.width + 'px';
        canvas.style.height = rect.height + 'px';

        const w = rect.width, h = rect.height;
        const pad = { top: 20, right: 20, bottom: 40, left: 45 };

        if (!trend || trend.length === 0) {
            ctx.fillStyle = '#64748b';
            ctx.font = '500 13px Inter';
            ctx.textAlign = 'center';
            ctx.fillText('No trend data yet — start scanning emails', w / 2, h / 2);
            return;
        }

        const counts = trend.map(d => d.count || 0);
        const threats = trend.map(d => d.threat_count || 0);
        const scores = trend.map(d => d.avg_score || 0);
        const maxCount = Math.max(...counts, 1);
        const chartW = w - pad.left - pad.right;
        const chartH = h - pad.top - pad.bottom;

        // Grid lines
        ctx.strokeStyle = 'rgba(100,120,180,0.08)';
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
            const y = pad.top + (chartH / 4) * i;
            ctx.beginPath();
            ctx.moveTo(pad.left, y);
            ctx.lineTo(w - pad.right, y);
            ctx.stroke();
        }

        const n = trend.length;
        const barW = Math.min(18, chartW / n - 4);

        // Scan count bars (cyan)
        trend.forEach((d, i) => {
            const x = pad.left + (i + 0.5) * (chartW / n);
            const barH = ((d.count || 0) / maxCount) * chartH;
            const y = pad.top + chartH - barH;
            const grad = ctx.createLinearGradient(x, y, x, pad.top + chartH);
            grad.addColorStop(0, 'rgba(6,182,212,0.5)');
            grad.addColorStop(1, 'rgba(6,182,212,0.05)');
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.roundRect(x - barW / 2, y, barW, barH, [3, 3, 0, 0]);
            ctx.fill();
        });

        // Threat bars (red, smaller)
        trend.forEach((d, i) => {
            const x = pad.left + (i + 0.5) * (chartW / n);
            const barH = ((d.threat_count || 0) / maxCount) * chartH;
            const y = pad.top + chartH - barH;
            ctx.fillStyle = 'rgba(239,68,68,0.55)';
            ctx.beginPath();
            ctx.roundRect(x - barW / 4, y, barW / 2, barH, [2, 2, 0, 0]);
            ctx.fill();
        });

        // Avg score line (purple)
        if (n > 1) {
            ctx.beginPath();
            ctx.strokeStyle = '#8b5cf6';
            ctx.lineWidth = 2;
            ctx.setLineDash([]);
            trend.forEach((d, i) => {
                const x = pad.left + (i + 0.5) * (chartW / n);
                const y = pad.top + chartH - ((d.avg_score || 0) / 100) * chartH;
                i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
            });
            ctx.stroke();
            trend.forEach((d, i) => {
                const x = pad.left + (i + 0.5) * (chartW / n);
                const y = pad.top + chartH - ((d.avg_score || 0) / 100) * chartH;
                ctx.beginPath();
                ctx.arc(x, y, 2.5, 0, Math.PI * 2);
                ctx.fillStyle = '#8b5cf6';
                ctx.fill();
            });
        }

        // X-axis date labels (show every 5th)
        ctx.fillStyle = '#64748b';
        ctx.font = '500 9px Inter';
        ctx.textAlign = 'center';
        trend.forEach((d, i) => {
            if (i % Math.ceil(n / 8) === 0 || i === n - 1) {
                const x = pad.left + (i + 0.5) * (chartW / n);
                ctx.fillText(d.date ? d.date.slice(5) : '', x, h - pad.bottom + 16);
            }
        });

        // Y-axis labels
        ctx.fillStyle = '#64748b';
        ctx.font = '500 9px "JetBrains Mono"';
        ctx.textAlign = 'right';
        for (let i = 0; i <= 4; i++) {
            const val = Math.round((maxCount / 4) * (4 - i));
            const y = pad.top + (chartH / 4) * i + 3;
            ctx.fillText(val, pad.left - 5, y);
        }
    },

    _renderRiskChart(breakdown) {
        const canvas = document.getElementById('risk-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);
        canvas.style.width = rect.width + 'px';
        canvas.style.height = rect.height + 'px';

        const levels = ['safe', 'low', 'medium', 'high', 'critical'];
        const colors = ['#22c55e', '#84cc16', '#eab308', '#f97316', '#ef4444'];
        const data = levels.map(l => breakdown[l] || 0);
        const total = data.reduce((a, b) => a + b, 0);

        const cx = rect.width / 2;
        const cy = (rect.height - 30) / 2 + 5;
        const radius = Math.min(cx, cy) - 15;
        const inner = radius * 0.58;

        if (total === 0) {
            ctx.fillStyle = '#64748b';
            ctx.font = '500 13px Inter';
            ctx.textAlign = 'center';
            ctx.fillText('No data yet', cx, cy + 5);
            return;
        }

        let startAngle = -Math.PI / 2;
        data.forEach((val, i) => {
            if (!val) return;
            const slice = (val / total) * Math.PI * 2;
            ctx.beginPath();
            ctx.arc(cx, cy, radius, startAngle, startAngle + slice);
            ctx.arc(cx, cy, inner, startAngle + slice, startAngle, true);
            ctx.closePath();
            ctx.fillStyle = colors[i];
            ctx.fill();
            startAngle += slice;
        });

        ctx.fillStyle = '#f1f5f9';
        ctx.font = '700 20px "JetBrains Mono"';
        ctx.textAlign = 'center';
        ctx.fillText(total, cx, cy + 7);
        ctx.fillStyle = '#94a3b8';
        ctx.font = '500 10px Inter';
        ctx.fillText('total', cx, cy + 21);

        // Legend below
        const legendY = rect.height - 8;
        ctx.font = '500 9px Inter';
        let legendX = 10;
        levels.forEach((level, i) => {
            if (!data[i]) return;
            ctx.fillStyle = colors[i];
            ctx.fillRect(legendX, legendY - 8, 7, 7);
            ctx.fillStyle = '#94a3b8';
            ctx.fillText(`${level}(${data[i]})`, legendX + 10, legendY);
            legendX += ctx.measureText(`${level}(${data[i]})`).width + 20;
        });
    },

    _renderCategoryChart(cats) {
        const canvas = document.getElementById('category-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);
        canvas.style.width = rect.width + 'px';
        canvas.style.height = rect.height + 'px';

        const entries = Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 6);
        const w = rect.width, h = rect.height;
        const pad = { top: 15, right: 20, bottom: 15, left: 80 };

        if (!entries.length) {
            ctx.fillStyle = '#64748b';
            ctx.font = '500 12px Inter';
            ctx.textAlign = 'center';
            ctx.fillText('No category data yet', w / 2, h / 2);
            return;
        }

        const colors = ['#06b6d4', '#8b5cf6', '#ec4899', '#f59e0b', '#22c55e', '#f97316'];
        const maxVal = entries[0][1];
        const chartW = w - pad.left - pad.right;
        const barH = Math.min(20, (h - pad.top - pad.bottom) / entries.length - 6);
        const gap = (h - pad.top - pad.bottom - entries.length * barH) / (entries.length + 1);

        entries.forEach(([cat, count], i) => {
            const y = pad.top + gap * (i + 1) + barH * i;
            const barW = (count / maxVal) * chartW;

            // Background track
            ctx.fillStyle = 'rgba(100,120,180,0.08)';
            ctx.beginPath();
            ctx.roundRect(pad.left, y, chartW, barH, 4);
            ctx.fill();

            // Bar
            const grad = ctx.createLinearGradient(pad.left, y, pad.left + barW, y);
            grad.addColorStop(0, colors[i % colors.length]);
            grad.addColorStop(1, colors[i % colors.length] + '80');
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.roundRect(pad.left, y, barW, barH, 4);
            ctx.fill();

            // Label
            ctx.fillStyle = '#94a3b8';
            ctx.font = '500 10px Inter';
            ctx.textAlign = 'right';
            ctx.fillText(cat, pad.left - 6, y + barH / 2 + 4);

            // Count
            ctx.fillStyle = '#f1f5f9';
            ctx.font = '600 9px "JetBrains Mono"';
            ctx.textAlign = 'left';
            ctx.fillText(count, pad.left + barW + 6, y + barH / 2 + 4);
        });
    },

    _renderAttackSources(sources) {
        const el = document.getElementById('attack-sources-list');
        const countEl = document.getElementById('attack-sources-count');
        if (!el) return;

        if (countEl) countEl.textContent = sources.length;

        if (!sources.length) {
            el.innerHTML = `<div class="empty-mini">No attack source data yet</div>`;
            return;
        }

        const maxCount = sources[0].count;
        el.innerHTML = sources.slice(0, 8).map((s, i) => {
            const pct = Math.round((s.count / maxCount) * 100);
            const threatPct = s.count > 0 ? Math.round((s.threat_count / s.count) * 100) : 0;
            const riskColor = threatPct > 70 ? '#ef4444' : threatPct > 40 ? '#f97316' : '#eab308';
            return `
                <div class="attack-source-item">
                    <div class="attack-source-header">
                        <span class="attack-source-domain" title="${this._esc(s.domain)}">
                            ${i < 3 ? '🔥' : '📧'} ${this._esc(s.domain)}
                        </span>
                        <div style="display:flex;gap:var(--space-sm);align-items:center">
                            <span style="font-size:0.75rem;color:#94a3b8">${s.count} emails</span>
                            <span style="font-size:0.7rem;padding:1px 6px;border-radius:9999px;background:${riskColor}22;color:${riskColor}">${threatPct}% threat</span>
                        </div>
                    </div>
                    <div class="attack-source-bar">
                        <div class="attack-source-fill" style="width:${pct}%;background:${riskColor}"></div>
                    </div>
                </div>
            `;
        }).join('');
    },

    _renderScoreDistribution(dist) {
        const canvas = document.getElementById('score-dist-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);
        canvas.style.width = rect.width + 'px';
        canvas.style.height = rect.height + 'px';

        const labels = ['0-20', '20-40', '40-60', '60-80', '80-100'];
        const colors = ['#22c55e', '#84cc16', '#eab308', '#f97316', '#ef4444'];
        const values = labels.map(l => dist[l] || 0);
        const max = Math.max(...values, 1);

        const w = rect.width, h = rect.height;
        const pad = { top: 15, right: 15, bottom: 35, left: 35 };
        const chartW = w - pad.left - pad.right;
        const chartH = h - pad.top - pad.bottom;
        const barW = chartW / labels.length - 8;

        // Grid
        ctx.strokeStyle = 'rgba(100,120,180,0.08)';
        ctx.lineWidth = 1;
        for (let i = 0; i <= 3; i++) {
            const y = pad.top + (chartH / 3) * i;
            ctx.beginPath();
            ctx.moveTo(pad.left, y);
            ctx.lineTo(w - pad.right, y);
            ctx.stroke();
        }

        labels.forEach((label, i) => {
            const x = pad.left + i * (chartW / labels.length) + 4;
            const barH = (values[i] / max) * chartH;
            const y = pad.top + chartH - barH;

            const grad = ctx.createLinearGradient(x, y, x, pad.top + chartH);
            grad.addColorStop(0, colors[i]);
            grad.addColorStop(1, colors[i] + '33');
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.roundRect(x, y, barW, barH, [3, 3, 0, 0]);
            ctx.fill();

            // Value above bar
            if (values[i] > 0) {
                ctx.fillStyle = colors[i];
                ctx.font = '600 9px "JetBrains Mono"';
                ctx.textAlign = 'center';
                ctx.fillText(values[i], x + barW / 2, y - 4);
            }

            // X-axis label
            ctx.fillStyle = '#64748b';
            ctx.font = '500 9px Inter';
            ctx.textAlign = 'center';
            ctx.fillText(label, x + barW / 2, h - pad.bottom + 15);
        });

        // Y-axis labels
        ctx.fillStyle = '#64748b';
        ctx.font = '500 9px "JetBrains Mono"';
        ctx.textAlign = 'right';
        for (let i = 0; i <= 3; i++) {
            const val = Math.round((max / 3) * (3 - i));
            ctx.fillText(val, pad.left - 4, pad.top + (chartH / 3) * i + 4);
        }
    },

    _renderGatewayStats(stats) {
        const el = document.getElementById('gateway-stats-panel');
        if (!el) return;

        const allowed = stats.allowed || 0;
        const quarantined = stats.quarantined || 0;
        const blocked = stats.blocked || 0;
        const total = allowed + quarantined + blocked;

        if (total === 0) {
            el.innerHTML = `
                <div class="empty-mini">No emails processed by gateway yet.</div>
                <p style="color:var(--text-muted);font-size:0.8rem;margin-top:var(--space-sm)">
                    Configure your mail server to forward emails to <code>/api/gateway/ingest</code>
                </p>
                <a href="#/gateway" class="btn btn-secondary btn-sm" style="margin-top:var(--space-md)">Configure Gateway →</a>
            `;
            return;
        }

        el.innerHTML = `
            <div class="gateway-stat-row">
                <div class="gateway-stat-item" style="--c:#22c55e">
                    <div class="gateway-stat-value">${allowed}</div>
                    <div class="gateway-stat-label">✅ Allowed</div>
                </div>
                <div class="gateway-stat-item" style="--c:#f97316">
                    <div class="gateway-stat-value">${quarantined}</div>
                    <div class="gateway-stat-label">⚠️ Quarantined</div>
                </div>
                <div class="gateway-stat-item" style="--c:#ef4444">
                    <div class="gateway-stat-value">${blocked}</div>
                    <div class="gateway-stat-label">🚫 Blocked</div>
                </div>
            </div>
            <div style="margin-top:var(--space-md)">
                <div style="display:flex;height:8px;border-radius:99px;overflow:hidden;gap:2px">
                    ${allowed ? `<div style="flex:${allowed};background:#22c55e;border-radius:99px 0 0 99px"></div>` : ''}
                    ${quarantined ? `<div style="flex:${quarantined};background:#f97316"></div>` : ''}
                    ${blocked ? `<div style="flex:${blocked};background:#ef4444;border-radius:0 99px 99px 0"></div>` : ''}
                </div>
                <div style="display:flex;justify-content:space-between;margin-top:var(--space-xs)">
                    <span style="font-size:0.75rem;color:var(--text-muted)">${total} total processed</span>
                    <a href="#/gateway" style="font-size:0.75rem">View logs →</a>
                </div>
            </div>
        `;
    },

    _renderUserReportsPanel(count, byType) {
        const el = document.getElementById('user-reports-panel');
        if (!el) return;

        if (count === 0) {
            el.innerHTML = `<div class="empty-mini">No user reports submitted yet.</div>`;
            return;
        }

        const fp = byType.false_positive || 0;
        const mt = byType.missed_threat || 0;
        const gen = byType.general || 0;

        el.innerHTML = `
            <div class="reports-summary">
                <div class="report-type-item">
                    <span class="report-type-dot" style="background:#22c55e"></span>
                    <span>False Positives</span>
                    <span class="report-type-count">${fp}</span>
                </div>
                <div class="report-type-item">
                    <span class="report-type-dot" style="background:#ef4444"></span>
                    <span>Missed Threats</span>
                    <span class="report-type-count">${mt}</span>
                </div>
                <div class="report-type-item">
                    <span class="report-type-dot" style="background:#94a3b8"></span>
                    <span>General</span>
                    <span class="report-type-count">${gen}</span>
                </div>
            </div>
            <a href="#/threat-intel" class="btn btn-secondary btn-sm" style="margin-top:var(--space-md)">View All Reports →</a>
        `;
    },

    _renderRecentScans(scans) {
        const container = document.getElementById('recent-scans-table');
        if (!container) return;

        if (!scans.length) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">📭</div>
                    <div class="empty-state-title">No scans yet</div>
                    <div class="empty-state-text">Upload an email file or paste email content to start analyzing for phishing threats.</div>
                    <a href="#/scan" class="btn btn-primary">Start Scanning</a>
                </div>
            `;
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
                    </tr>
                </thead>
                <tbody>
                    ${scans.map(s => `
                        <tr style="cursor:pointer" onclick="location.hash='#/history/${s.id}'">
                            <td class="cell-subject">${this._esc(s.subject || '(no subject)')}</td>
                            <td class="cell-sender">${this._esc(s.sender || '—')}</td>
                            <td><span class="risk-badge ${s.risk_level}">${s.risk_level}</span></td>
                            <td class="cell-score">${s.risk_score}</td>
                            <td><span class="source-badge ${s.source}">${s.source}</span></td>
                            <td class="cell-date">${this._formatDate(s.created_at)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    },

    _showEmptyDashboard() {
        ['stat-total','stat-threats','stat-safe','stat-reports','stat-gateway'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = '0';
        });
        const scoreEl = document.getElementById('stat-avgscore');
        if (scoreEl) scoreEl.textContent = '0.0';
        this._renderRiskChart({});
        this._renderTrendChart([]);
        this._renderRecentScans([]);
    },

    _esc(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    _formatDate(dateStr) {
        if (!dateStr) return '—';
        try {
            return new Date(dateStr).toLocaleDateString('en-US', {
                month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
            });
        } catch { return dateStr; }
    }
};
