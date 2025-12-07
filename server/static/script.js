document.addEventListener('DOMContentLoaded', () => {
    // Navigation
    const navItems = document.querySelectorAll('.nav-item');
    const views = document.querySelectorAll('.view');
    const pageTitle = document.getElementById('page-title');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const tab = item.dataset.tab;

            // Update Nav
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            // Update View
            views.forEach(v => v.classList.remove('active'));
            const targetView = document.getElementById(`view-${tab}`);
            if (targetView) targetView.classList.add('active');

            // Update Title
            pageTitle.textContent = tab.charAt(0).toUpperCase() + tab.slice(1);
        });
    });

    // Data Fetching
    function fetchStats() {
        fetch('/api/ui/stats')
            .then(res => res.json())
            .then(data => {
                document.getElementById('stat-total-agents').textContent = data.total_agents;
                document.getElementById('stat-online-agents').textContent = data.online_agents;
                document.getElementById('stat-active-alerts').textContent = data.active_alerts;
                document.getElementById('stat-critical-alerts').textContent = data.critical_alerts;
            });
    }

    function fetchAlerts() {
        fetch('/api/ui/alerts')
            .then(res => res.json())
            .then(data => {
                const container = document.getElementById('dashboard-alerts');
                const allContainer = document.getElementById('all-alerts');

                const html = data.map(alert => `
                    <div class="alert-item">
                        <div class="alert-left">
                            <span class="severity-badge severity-${alert.severity.toLowerCase()}">${alert.severity}</span>
                            <div class="alert-info">
                                <h4>${alert.title}</h4>
                                <p>${alert.description} • ${alert.agent}</p>
                                <div class="alert-details" style="font-size: 0.8rem; color: #64748b; margin-top: 5px; font-family: monospace;">
                                    ${alert.details.hash ? `<div>Hash: ${alert.details.hash.substring(0, 16)}...</div>` : ''}
                                    ${alert.details.cpu ? `<div>CPU: ${alert.details.cpu}% | Mem: ${alert.details.memory.toFixed(1)}%</div>` : ''}
                                    ${alert.details.cmdline ? `<div>Cmd: ${alert.details.cmdline.substring(0, 50)}...</div>` : ''}
                                    ${alert.details.raddr ? `<div>Net: ${alert.details.laddr} -> ${alert.details.raddr}</div>` : ''}
                                </div>
                            </div>
                        </div>
                        <div class="alert-meta">
                            <div>${new Date(alert.timestamp).toLocaleTimeString()}</div>
                            <div>${alert.status}</div>
                        </div>
                    </div>
                `).join('');

                container.innerHTML = html;
                if (allContainer) allContainer.innerHTML = html;
            });
    }

    function fetchAgents() {
        fetch('/api/ui/agents')
            .then(res => res.json())
            .then(data => {
                const container = document.getElementById('all-agents');
                container.innerHTML = data.map(agent => `
                    <div class="agent-card">
                        <div class="agent-header">
                            <h3>${agent.hostname}</h3>
                            <div class="agent-status status-${agent.status}"></div>
                        </div>
                        <p style="color: #94a3b8; font-size: 0.9rem;">${agent.ip}</p>
                        <p style="color: #94a3b8; font-size: 0.9rem; margin-top: 5px;">${agent.os}</p>
                        <div style="margin-top: 1rem; font-size: 0.8rem; color: #64748b;">
                            Last seen: ${new Date(agent.last_seen).toLocaleString()}
                        </div>
                    </div>
                `).join('');
            });
    }

    // Initial Load
    fetchStats();
    fetchAlerts();
    fetchAgents();

    // Polling
    setInterval(() => {
        fetchStats();
        fetchAlerts();
        fetchAgents();
    }, 2000);
});
