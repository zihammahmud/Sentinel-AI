let attackCy = null;
let attackUpdateInterval = null;

const deviceColors = {
    'Workstation': '#3b82f6',
    'Laptop': '#8b5cf6',
    'Server': '#10b981',
    'Database': '#f59e0b',
    'Router': '#06b6d4',
    'Firewall': '#ef4444',
    'IoT Device': '#ec4899'
};

const attackStages = [
    'Attack Started',
    'Initial Device Compromised',
    'Suspicious Activity Detected',
    'Network Investigation',
    'Possible Propagation',
    'Risk Assessment',
    'Defensive Decision',
    'Threat Contained'
];

const attackDescriptions = {
    'malware_propagation': {
        name: 'Malware Propagation',
        desc: 'Self-replicating malware that spreads through network connections. High propagation rate.',
        severity: 'High'
    },
    'ransomware': {
        name: 'Ransomware Simulation',
        desc: 'Encrypts files and demands ransom. Moderate spread, high impact on availability.',
        severity: 'Critical'
    },
    'ddos': {
        name: 'DDoS Simulation',
        desc: 'Distributed Denial of Service. Floods target with traffic. No propagation.',
        severity: 'High'
    },
    'insider_threat': {
        name: 'Insider Threat',
        desc: 'Malicious insider with privileged access. Low spread, difficult to detect.',
        severity: 'Medium'
    },
    'phishing': {
        name: 'Phishing-Based Compromise',
        desc: 'Credential harvesting via social engineering. Moderate spread after initial compromise.',
        severity: 'Medium'
    }
};

document.addEventListener('DOMContentLoaded', function() {
    loadDeviceSelects();
    initAttackGraph();
    loadAttackHistory();
    updateAttackInfo();

    document.getElementById('attack-type').addEventListener('change', updateAttackInfo);
    document.getElementById('attack-form').addEventListener('submit', launchAttack);

    attackUpdateInterval = setInterval(() => {
        loadAttackHistory();
        updateAttackProgress();
        updateAttackGraph();
    }, 2000);
});

function updateAttackInfo() {
    const type = document.getElementById('attack-type').value;
    const info = attackDescriptions[type];
    document.getElementById('attack-info').innerHTML = `
        <h6 class="text-danger">${info.name}</h6>
        <p class="small text-secondary mb-1">${info.desc}</p>
        <span class="badge bg-danger">Severity: ${info.severity}</span>
    `;
}

async function loadDeviceSelects() {
    try {
        const response = await fetch('/api/devices');
        const devices = await response.json();

        const sourceSel = document.getElementById('attack-source');
        const targetSel = document.getElementById('attack-target');

        sourceSel.innerHTML = devices.map(d => 
            `<option value="${d.id}">${d.name} (${d.type}) [${d.ip_address}]</option>`
        ).join('');

        targetSel.innerHTML = '<option value="">-- Select target --</option>' + 
            devices.map(d => `<option value="${d.id}">${d.name} (${d.type})</option>`).join('');
    } catch (e) {
        console.error('Error loading devices:', e);
    }
}

async function launchAttack(e) {
    e.preventDefault();
    const data = {
        attack_type: document.getElementById('attack-type').value,
        source_device: parseInt(document.getElementById('attack-source').value),
        target_device: document.getElementById('attack-target').value || null
    };

    if (data.target_device) data.target_device = parseInt(data.target_device);

    try {
        const response = await fetch('/api/start-attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        const result = await response.json();

        document.getElementById('simulation-status').textContent = 'RUNNING';
        document.getElementById('simulation-status').className = 'badge bg-danger';

        updateAttackProgress();
        loadAttackHistory();
    } catch (e) {
        console.error('Error launching attack:', e);
        alert('Failed to launch attack');
    }
}

async function stopAttack() {
    try {
        await fetch('/api/stop-attack', { method: 'POST' });
        document.getElementById('simulation-status').textContent = 'STOPPED';
        document.getElementById('simulation-status').className = 'badge bg-warning';
        document.getElementById('attack-progress-bar').style.width = '0%';
        document.getElementById('attack-progress-bar').textContent = 'Stopped';
        loadAttackHistory();
    } catch (e) {
        console.error('Error stopping attack:', e);
    }
}

async function updateAttackProgress() {
    try {
        const response = await fetch('/api/dashboard-stats');
        const stats = await response.json();

        const container = document.getElementById('attack-progress');
        const bar = document.getElementById('attack-progress-bar');

        if (!stats.active_attack) {
            container.innerHTML = '<div class="timeline-item"><div class="small text-secondary">No active simulation</div></div>';
            bar.style.width = '0%';
            bar.textContent = 'Idle';
            bar.className = 'progress-bar bg-secondary';
            return;
        }

        const stageIndex = stats.active_attack.stage_index || 0;
        const progress = ((stageIndex + 1) / attackStages.length) * 100;

        container.innerHTML = '';
        attackStages.forEach((stage, idx) => {
            const item = document.createElement('div');
            item.className = 'timeline-item';
            if (idx < stageIndex) item.classList.add('completed');
            else if (idx === stageIndex) item.classList.add('active');
            item.innerHTML = `<div class="small">${stage}</div>`;
            container.appendChild(item);
        });

        bar.style.width = progress + '%';
        bar.textContent = attackStages[stageIndex] || 'Complete';
        bar.className = 'progress-bar progress-bar-striped progress-bar-animated bg-danger';
    } catch (e) {
        console.error('Error updating progress:', e);
    }
}

async function loadAttackHistory() {
    try {
        const response = await fetch('/api/attacks');
        const attacks = await response.json();

        const tbody = document.getElementById('attack-history-body');
        tbody.innerHTML = attacks.map(a => {
            const statusBadge = a.status === 'active' ? 'bg-danger' : 
                               a.status === 'completed' ? 'bg-success' : 'bg-secondary';
            const typeLabel = attackDescriptions[a.attack_type]?.name || a.attack_type;
            return `<tr>
                <td>${a.id}</td>
                <td>${typeLabel}</td>
                <td><span class="badge bg-warning">${a.severity}</span></td>
                <td><span class="badge ${statusBadge}">${a.status}</span></td>
                <td>${a.current_stage}</td>
                <td>${new Date(a.start_time).toLocaleString()}</td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error('Error loading attack history:', e);
    }
}

function initAttackGraph() {
    attackCy = cytoscape({
        container: document.getElementById('attack-network-graph'),
        style: [
            {
                selector: 'node',
                style: {
                    'background-color': '#3b82f6',
                    'label': 'data(label)',
                    'color': '#fff',
                    'text-outline-color': '#000',
                    'text-outline-width': 2,
                    'font-size': '11px',
                    'width': 35,
                    'height': 35
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#374151',
                    'curve-style': 'bezier'
                }
            },
            {
                selector: '.compromised',
                style: {
                    'background-color': '#ef4444',
                    'border-width': 3,
                    'border-color': '#dc2626'
                }
            },
            {
                selector: '.newly-compromised',
                style: {
                    'background-color': '#f59e0b',
                    'border-width': 3,
                    'border-color': '#d97706',
                    'transition-property': 'background-color, border-color',
                    'transition-duration': '0.5s'
                }
            }
        ],
        layout: { name: 'cose', padding: 20 }
    });
}

async function updateAttackGraph() {
    try {
        const [devResponse, connResponse] = await Promise.all([
            fetch('/api/devices'),
            fetch('/api/connections')
        ]);
        const devices = await devResponse.json();
        const connections = await connResponse.json();

        attackCy.elements().remove();

        devices.forEach(d => {
            const color = deviceColors[d.type] || '#3b82f6';
            let cls = '';
            if (d.status === 'compromised') cls = 'compromised';

            attackCy.add({
                group: 'nodes',
                data: { id: 'a' + d.id, label: d.name, deviceId: d.id },
                position: { x: d.x || Math.random() * 600, y: d.y || Math.random() * 350 }
            });

            const node = attackCy.getElementById('a' + d.id);
            node.style('background-color', color);
            if (cls) node.addClass(cls);
        });

        connections.forEach(c => {
            attackCy.add({
                group: 'edges',
                data: { id: 'ae' + c.id, source: 'a' + c.source, target: 'a' + c.target }
            });
        });

        attackCy.layout({ name: 'cose', padding: 20, animate: true, animationDuration: 500 }).run();
    } catch (e) {
        console.error('Error updating attack graph:', e);
    }
}

async function isolateAllCompromised() {
    try {
        const response = await fetch('/api/devices');
        const devices = await response.json();
        const compromised = devices.filter(d => d.status === 'compromised' && !d.isolated);

        for (const d of compromised) {
            await fetch('/api/isolate-device/' + d.id, { method: 'POST' });
        }

        alert(`Isolated ${compromised.length} compromised devices`);
        updateAttackGraph();
    } catch (e) {
        console.error('Error isolating devices:', e);
    }
}

async function resetNetwork() {
    try {
        await fetch('/api/reset-network', { method: 'POST' });
        updateAttackGraph();
        loadAttackHistory();
        document.getElementById('simulation-status').textContent = 'Idle';
        document.getElementById('simulation-status').className = 'badge bg-secondary';
    } catch (e) {
        console.error('Error resetting network:', e);
    }
}