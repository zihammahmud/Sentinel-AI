let cy = null;
let statusChart = null;
let typeChart = null;
let vulnChart = null;
let updateInterval = null;

const deviceColors = {
    'Workstation': '#3b82f6',
    'Laptop': '#8b5cf6',
    'Server': '#10b981',
    'Database': '#f59e0b',
    'Router': '#06b6d4',
    'Firewall': '#ef4444',
    'IoT Device': '#ec4899'
};

const statusColors = {
    'healthy': '#10b981',
    'suspicious': '#f59e0b',
    'compromised': '#ef4444',
    'isolated': '#8b5cf6'
};

document.addEventListener('DOMContentLoaded', function() {
    initNetworkGraph();
    loadDashboardStats();
    loadEvents();
    updateInterval = setInterval(() => {
        loadDashboardStats();
        loadEvents();
        updateNetworkGraph();
    }, 3000);
});

function initNetworkGraph() {
    cy = cytoscape({
        container: document.getElementById('network-graph'),
        style: [
            {
                selector: 'node',
                style: {
                    'background-color': '#3b82f6',
                    'label': 'data(label)',
                    'color': '#fff',
                    'text-outline-color': '#000',
                    'text-outline-width': 2,
                    'font-size': '12px',
                    'width': 40,
                    'height': 40,
                    'border-width': 2,
                    'border-color': '#1f2937'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#374151',
                    'target-arrow-color': '#374151',
                    'target-arrow-shape': 'none',
                    'curve-style': 'bezier'
                }
            },
            {
                selector: '.compromised',
                style: {
                    'background-color': '#ef4444',
                    'border-color': '#dc2626',
                    'border-width': 3
                }
            },
            {
                selector: '.suspicious',
                style: {
                    'background-color': '#f59e0b',
                    'border-color': '#d97706',
                    'border-width': 3
                }
            },
            {
                selector: '.isolated',
                style: {
                    'background-color': '#8b5cf6',
                    'border-color': '#7c3aed',
                    'border-width': 3,
                    'border-style': 'dashed'
                }
            }
        ],
        layout: { name: 'cose', padding: 20 }
    });

    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        alert(`Device: ${node.data('label')}
Type: ${node.data('deviceType')}
IP: ${node.data('ip')}
Status: ${node.data('status')}
Vulnerability: ${node.data('vulnerability')}`);
    });
}

async function updateNetworkGraph() {
    try {
        const response = await fetch('/api/devices');
        const devices = await response.json();
        const connResponse = await fetch('/api/connections');
        const connections = await connResponse.json();

        const existingNodes = cy.nodes().map(n => n.id());
        const existingEdges = cy.edges().map(e => e.id());

        const newNodeIds = devices.map(d => 'n' + d.id);
        const newEdgeIds = connections.map(c => 'e' + c.id);

        // Remove old
        cy.nodes().forEach(n => {
            if (!newNodeIds.includes(n.id())) cy.remove(n);
        });
        cy.edges().forEach(e => {
            if (!newEdgeIds.includes(e.id())) cy.remove(e);
        });

        // Add/update nodes
        devices.forEach(d => {
            const nodeId = 'n' + d.id;
            const color = deviceColors[d.type] || '#3b82f6';
            const statusClass = d.status;

            if (cy.getElementById(nodeId).length === 0) {
                cy.add({
                    group: 'nodes',
                    data: {
                        id: nodeId,
                        label: d.name,
                        deviceType: d.type,
                        ip: d.ip_address,
                        status: d.status,
                        vulnerability: d.vulnerability_score
                    },
                    position: { x: d.x || Math.random() * 600, y: d.y || Math.random() * 400 }
                });
            } else {
                cy.getElementById(nodeId).data({
                    label: d.name,
                    deviceType: d.type,
                    ip: d.ip_address,
                    status: d.status,
                    vulnerability: d.vulnerability_score
                });
            }

            const node = cy.getElementById(nodeId);
            node.style('background-color', color);
            node.removeClass('compromised suspicious isolated healthy');
            if (d.isolated) node.addClass('isolated');
            else if (d.status === 'compromised') node.addClass('compromised');
            else if (d.status === 'suspicious') node.addClass('suspicious');
        });

        // Add/update edges
        connections.forEach(c => {
            const edgeId = 'e' + c.id;
            if (cy.getElementById(edgeId).length === 0) {
                cy.add({
                    group: 'edges',
                    data: {
                        id: edgeId,
                        source: 'n' + c.source,
                        target: 'n' + c.target
                    }
                });
            }
        });

        cy.layout({ name: 'cose', padding: 20, animate: true, animationDuration: 500 }).run();
    } catch (e) {
        console.error('Error updating network graph:', e);
    }
}

async function loadDashboardStats() {
    try {
        const response = await fetch('/api/dashboard-stats');
        const stats = await response.json();

        document.getElementById('stat-total').textContent = stats.total_devices;
        document.getElementById('stat-healthy').textContent = stats.healthy_devices;
        document.getElementById('stat-suspicious').textContent = stats.suspicious_devices;
        document.getElementById('stat-compromised').textContent = stats.compromised_devices;
        document.getElementById('stat-isolated').textContent = stats.isolated_devices;
        document.getElementById('stat-risk').textContent = stats.risk_score;

        const threatLevel = document.getElementById('threat-level');
        threatLevel.textContent = stats.threat_level;
        threatLevel.className = 'fw-bold ' + getThreatClass(stats.threat_level);

        const threatBar = document.getElementById('threat-bar');
        const threatWidth = stats.threat_level === 'Critical' ? 100 : stats.threat_level === 'High' ? 75 : stats.threat_level === 'Medium' ? 50 : 25;
        threatBar.style.width = threatWidth + '%';
        threatBar.className = 'progress-bar ' + getThreatBgClass(stats.threat_level);

        document.getElementById('risk-score-display').textContent = stats.risk_score + '/100';
        document.getElementById('risk-bar').style.width = Math.min(stats.risk_score, 100) + '%';
        document.getElementById('ai-recommendation').textContent = stats.ai_recommendation;

        // Update attack status
        const attackStatus = document.getElementById('attack-status');
        if (stats.active_attack) {
            attackStatus.textContent = 'ACTIVE: ' + stats.active_attack.type;
            attackStatus.className = 'badge bg-danger';
            updateAttackTimeline(stats.active_attack);
        } else {
            attackStatus.textContent = 'No Active Attack';
            attackStatus.className = 'badge bg-secondary';
        }

        updateCharts(stats);
    } catch (e) {
        console.error('Error loading stats:', e);
    }
}

function getThreatClass(level) {
    switch(level) {
        case 'Critical': return 'text-danger';
        case 'High': return 'text-warning';
        case 'Medium': return 'text-info';
        default: return 'text-success';
    }
}

function getThreatBgClass(level) {
    switch(level) {
        case 'Critical': return 'bg-danger';
        case 'High': return 'bg-warning';
        case 'Medium': return 'bg-info';
        default: return 'bg-success';
    }
}

function updateAttackTimeline(attack) {
    const stages = [
        'Attack Started',
        'Initial Device Compromised',
        'Suspicious Activity Detected',
        'Network Investigation',
        'Possible Propagation',
        'Risk Assessment',
        'Defensive Decision',
        'Threat Contained'
    ];

    const container = document.getElementById('attack-timeline');
    container.innerHTML = '';

    stages.forEach((stage, idx) => {
        const item = document.createElement('div');
        item.className = 'timeline-item';
        if (idx < attack.stage_index) item.classList.add('completed');
        else if (idx === attack.stage_index) item.classList.add('active');

        item.innerHTML = `<div class="small">${stage}</div>`;
        container.appendChild(item);
    });
}

async function loadEvents() {
    try {
        const response = await fetch('/api/events');
        const events = await response.json();
        const container = document.getElementById('event-log');

        if (events.length === 0) {
            container.innerHTML = '<div class="text-secondary small">No events recorded yet.</div>';
            return;
        }

        container.innerHTML = events.map(e => {
            let cls = '';
            if (e.event_type.includes('ATTACK')) cls = 'danger';
            else if (e.event_type.includes('AI')) cls = 'info';
            else if (e.event_type.includes('PROPAGATION')) cls = 'warning';

            const time = new Date(e.timestamp).toLocaleTimeString();
            return `<div class="event-item ${cls}">
                <span class="text-secondary">[${time}]</span> 
                <span class="text-info">${e.event_type}</span>: ${e.description}
            </div>`;
        }).join('');

        container.scrollTop = 0;
    } catch (e) {
        console.error('Error loading events:', e);
    }
}

async function updateCharts(stats) {
    try {
        const response = await fetch('/api/devices');
        const devices = await response.json();

        // Status chart
        const statusCounts = { healthy: 0, suspicious: 0, compromised: 0, isolated: 0 };
        devices.forEach(d => {
            if (d.isolated) statusCounts.isolated++;
            else if (statusCounts[d.status] !== undefined) statusCounts[d.status]++;
        });

        if (statusChart) statusChart.destroy();
        statusChart = new Chart(document.getElementById('statusChart'), {
            type: 'doughnut',
            data: {
                labels: ['Healthy', 'Suspicious', 'Compromised', 'Isolated'],
                datasets: [{
                    data: [statusCounts.healthy, statusCounts.suspicious, statusCounts.compromised, statusCounts.isolated],
                    backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#8b5cf6']
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { position: 'bottom', labels: { color: '#fff' } } }
            }
        });

        // Type chart
        const typeCounts = {};
        devices.forEach(d => { typeCounts[d.type] = (typeCounts[d.type] || 0) + 1; });

        if (typeChart) typeChart.destroy();
        typeChart = new Chart(document.getElementById('typeChart'), {
            type: 'bar',
            data: {
                labels: Object.keys(typeCounts),
                datasets: [{
                    label: 'Count',
                    data: Object.values(typeCounts),
                    backgroundColor: Object.keys(typeCounts).map(t => deviceColors[t] || '#3b82f6')
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
                    x: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }
                }
            }
        });

        // Vulnerability chart
        const vulnData = devices.map(d => d.vulnerability_score);
        const vulnLabels = devices.map(d => d.name);

        if (vulnChart) vulnChart.destroy();
        vulnChart = new Chart(document.getElementById('vulnChart'), {
            type: 'line',
            data: {
                labels: vulnLabels,
                datasets: [{
                    label: 'Vulnerability Score',
                    data: vulnData,
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { min: 0, max: 1, ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
                    x: { ticks: { color: '#9ca3af', maxRotation: 45 }, grid: { color: '#374151' } }
                }
            }
        });
    } catch (e) {
        console.error('Error updating charts:', e);
    }
}

async function seedNetwork() {
    try {
        await fetch('/api/seed-network', { method: 'POST' });
        updateNetworkGraph();
        loadDashboardStats();
    } catch (e) {
        console.error('Error seeding network:', e);
    }
}

async function resetNetwork() {
    try {
        await fetch('/api/reset-network', { method: 'POST' });
        updateNetworkGraph();
        loadDashboardStats();
    } catch (e) {
        console.error('Error resetting network:', e);
    }
}
