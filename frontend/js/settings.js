/**
 * PhishingPro — Settings Page
 */

const SettingsPage = {
    render() {
        return `
            <div class="page-header">
                <h1 class="page-title">Settings</h1>
                <p class="page-subtitle">Configure PhishingPro options</p>
            </div>

            <div class="card settings-section">
                <div class="settings-section-title">🔗 VirusTotal Integration</div>
                <p style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:var(--space-md)">
                    Add your VirusTotal API key to enable real-time URL reputation scanning.
                    <a href="https://www.virustotal.com/gui/join-us" target="_blank">Get a free key →</a>
                </p>
                <div class="form-row">
                    <div class="form-group" style="flex:1;margin-bottom:0">
                        <label class="form-label" for="vt-api-key">API Key</label>
                        <input type="password" class="form-input" id="vt-api-key" placeholder="Enter your VirusTotal API key">
                    </div>
                    <button class="btn btn-primary" id="save-vt-key" style="margin-bottom:0">Save Key</button>
                </div>
                <div class="connection-status" id="vt-status" style="margin-top:var(--space-md)">
                    <span class="status-dot disconnected" id="vt-status-dot"></span>
                    <span id="vt-status-text">Checking...</span>
                </div>
            </div>

            <div class="card settings-section">
                <div class="settings-section-title">🗄️ Data Management</div>
                <p style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:var(--space-lg)">
                    Manage your scan history data stored locally.
                </p>
                <div style="display:flex;gap:var(--space-md)">
                    <button class="btn btn-danger" id="clear-data-btn">🗑️ Clear All Scan Data</button>
                </div>
            </div>

            <div class="card settings-section">
                <div class="settings-section-title">ℹ️ About</div>
                <div style="color:var(--text-secondary);font-size:0.9rem;line-height:1.8">
                    <p><strong>PhishingPro</strong> v1.0.0</p>
                    <p>Multi-layered email phishing detector with header analysis, URL scanning, NLP content analysis, and email authentication verification.</p>
                    <p style="margin-top:var(--space-md)">
                        <strong>Detection Layers:</strong><br>
                        📋 Header Analyzer — Spoofing, impersonation, anomalies<br>
                        🔗 URL Analyzer — Phishing links, shorteners, brand impersonation<br>
                        📝 Content Analyzer — Urgency language, credential requests, social engineering<br>
                        🔐 Auth Checker — SPF, DKIM, DMARC verification
                    </p>
                </div>
            </div>
        `;
    },

    async mount() {
        this._setupSaveKey();
        this._setupClearData();
        await this._loadSettings();
    },

    async _loadSettings() {
        try {
            const settings = await API.getSettings();
            const dot = document.getElementById('vt-status-dot');
            const text = document.getElementById('vt-status-text');

            if (settings.virustotal_configured) {
                dot.classList.remove('disconnected');
                dot.classList.add('connected');
                text.textContent = `Configured (${settings.virustotal_api_key})`;
            } else {
                dot.classList.remove('connected');
                dot.classList.add('disconnected');
                text.textContent = 'Not configured';
            }
        } catch (err) {
            document.getElementById('vt-status-text').textContent = 'Error loading settings';
        }
    },

    _setupSaveKey() {
        const btn = document.getElementById('save-vt-key');
        if (btn) {
            btn.addEventListener('click', async () => {
                const input = document.getElementById('vt-api-key');
                const key = input ? input.value.trim() : '';

                if (!key) {
                    App.toast('Please enter an API key', 'warning');
                    return;
                }

                try {
                    await API.updateSettings({ virustotal_api_key: key });
                    App.toast('API key saved successfully', 'success');
                    input.value = '';
                    await this._loadSettings();
                } catch (err) {
                    App.toast(`Failed: ${err.message}`, 'error');
                }
            });
        }
    },

    _setupClearData() {
        const btn = document.getElementById('clear-data-btn');
        if (btn) {
            btn.addEventListener('click', async () => {
                if (confirm('Are you sure you want to clear ALL scan data? This cannot be undone.')) {
                    try {
                        await API.clearHistory();
                        App.toast('All data cleared', 'success');
                    } catch (err) {
                        App.toast(`Failed: ${err.message}`, 'error');
                    }
                }
            });
        }
    },
};
