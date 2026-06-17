/**
 * PhishingPro — App Router & Bootstrap
 * Client-side hash router with page lifecycle management.
 */

const App = {
    _currentPage: null,

    pages: {
        dashboard: DashboardPage,
        scan: ScannerPage,
        history: HistoryPage,
        settings: SettingsPage,
        'threat-intel': ThreatIntelPage,
        gateway: GatewayPage,
    },

    init() {
        window.addEventListener('hashchange', () => this._onRouteChange());

        // Mobile menu toggle
        this._setupMobileMenu();

        // Set initial route
        if (!location.hash || location.hash === '#/') {
            location.hash = '#/dashboard';
        } else {
            this._onRouteChange();
        }
    },

    _setupMobileMenu() {
        const btn = document.getElementById('mobile-menu-btn');
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebar-overlay');

        if (btn && sidebar) {
            btn.addEventListener('click', () => {
                sidebar.classList.toggle('open');
                overlay?.classList.toggle('open');
            });
        }

        if (overlay) {
            overlay.addEventListener('click', () => {
                sidebar?.classList.remove('open');
                overlay.classList.remove('open');
            });
        }

        // Close sidebar on nav click (mobile)
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', () => {
                if (window.innerWidth <= 768) {
                    sidebar?.classList.remove('open');
                    overlay?.classList.remove('open');
                }
            });
        });
    },

    _onRouteChange() {
        const hash = location.hash.replace('#/', '') || 'dashboard';
        const pageName = hash.split('/')[0]; // Handle #/history/123

        // Update nav
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.toggle('active', link.dataset.page === pageName);
        });

        const page = this.pages[pageName];
        if (!page) {
            location.hash = '#/dashboard';
            return;
        }

        // Render page with transition
        const main = document.getElementById('main-content');
        if (main) {
            main.classList.add('page-exit');
            setTimeout(() => {
                main.innerHTML = page.render();
                main.classList.remove('page-exit');
                main.classList.add('page-enter');
                // Mount with slight delay for DOM to settle
                requestAnimationFrame(() => {
                    if (page.mount) page.mount();
                    setTimeout(() => main.classList.remove('page-enter'), 300);
                });
            }, 150);
        }

        this._currentPage = pageName;
    },

    toast(message, type = 'info', duration = 4000) {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <span>${icons[type] || ''}</span>
            <span style="flex:1">${message}</span>
            <button class="toast-close" onclick="this.parentElement.remove()">×</button>
        `;

        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100px)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },
};

// Boot the app
document.addEventListener('DOMContentLoaded', () => App.init());
