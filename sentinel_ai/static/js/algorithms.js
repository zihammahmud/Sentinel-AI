let devices = [];

document.addEventListener('DOMContentLoaded', function() {
    loadAlgorithmDevices();
    setInterval(loadAlgorithmDevices, 5000);
    loadAlgorithmLog();
    setInterval(loadAlgorithmLog, 3000);
});

async function loadAlgorithmDevices() {
    try {
        const response = await fetch('/api/devices');
        devices = await response.json();

        const selects = ['bfs-start', 'dfs-start', 'dls-start', 'ids-start', 'astar-start', 'astar-goal', 'bayesian-device'];
        selects.forEach(id => {
            const sel = document.getElementById(id);
            if (!sel) return;
            const currentVal = sel.value;
            sel.innerHTML = devices.map(d => 
                `<option value="${d.id}">${d.id}: ${d.name} (${d.type})</option>`
            ).join('');
            if (currentVal) sel.value = currentVal;
        });
    } catch (e) {
        console.error('Error loading devices:', e);
    }
}

async function loadAlgorithmLog() {
    try {
        const response = await fetch('/api/events');
        const events = await response.json();
        const container = document.getElementById('algorithm-log');

        const aiEvents = events.filter(e => e.event_type.startsWith('AI_'));

        if (aiEvents.length === 0) {
            container.innerHTML = '<div class="text-secondary small">Run algorithms to see results here.</div>';
            return;
        }

        container.innerHTML = aiEvents.map(e => {
            const time = new Date(e.timestamp).toLocaleTimeString();
            return `<div class="event-item info">
                <span class="text-secondary">[${time}]</span> 
                <span class="text-info">${e.event_type}</span>: ${e.description}
            </div>`;
        }).join('');
    } catch (e) {
        console.error('Error loading algorithm log:', e);
    }
}

function showResult(elementId, data) {
    const el = document.getElementById(elementId);
    el.classList.remove('d-none');
    el.innerHTML = '<pre class="mb-0 text-light">' + JSON.stringify(data, null, 2) + '</pre>';
}

async function runBFS() {
    const startNode = parseInt(document.getElementById('bfs-start').value);
    try {
        const response = await fetch('/api/ai/bfs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ start_node: startNode })
        });
        const result = await response.json();
        showResult('bfs-result', result);
        loadAlgorithmLog();
    } catch (e) {
        console.error('BFS error:', e);
    }
}

async function runDFS() {
    const startNode = parseInt(document.getElementById('dfs-start').value);
    try {
        const response = await fetch('/api/ai/dfs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ start_node: startNode })
        });
        const result = await response.json();
        showResult('dfs-result', result);
        loadAlgorithmLog();
    } catch (e) {
        console.error('DFS error:', e);
    }
}

async function runDLS() {
    const startNode = parseInt(document.getElementById('dls-start').value);
    const limit = parseInt(document.getElementById('dls-limit').value);
    try {
        const response = await fetch('/api/ai/dls', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ start_node: startNode, limit: limit })
        });
        const result = await response.json();
        showResult('dls-result', result);
        loadAlgorithmLog();
    } catch (e) {
        console.error('DLS error:', e);
    }
}

async function runIDS() {
    const startNode = parseInt(document.getElementById('ids-start').value);
    const maxDepth = parseInt(document.getElementById('ids-max-depth').value);
    try {
        const response = await fetch('/api/ai/ids', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ start_node: startNode, max_depth: maxDepth })
        });
        const result = await response.json();
        showResult('ids-result', result);
        loadAlgorithmLog();
    } catch (e) {
        console.error('IDS error:', e);
    }
}

async function runAStar() {
    const startNode = parseInt(document.getElementById('astar-start').value);
    const goalNode = parseInt(document.getElementById('astar-goal').value);

    if (startNode === goalNode) {
        alert('Start and goal must be different');
        return;
    }

    try {
        const response = await fetch('/api/ai/astar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ start_node: startNode, goal_node: goalNode })
        });
        const result = await response.json();
        showResult('astar-result', result);
        loadAlgorithmLog();
    } catch (e) {
        console.error('A* error:', e);
    }
}

async function runBayesian() {
    const deviceId = parseInt(document.getElementById('bayesian-device').value);
    try {
        const response = await fetch('/api/ai/bayesian', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device_id: deviceId })
        });
        const result = await response.json();
        showResult('bayesian-result', result);
        loadAlgorithmLog();
    } catch (e) {
        console.error('Bayesian error:', e);
    }
}

async function runAlphaBeta() {
    try {
        const response = await fetch('/api/ai/alphabeta', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const result = await response.json();
        showResult('alphabeta-result', result);
        loadAlgorithmLog();
    } catch (e) {
        console.error('Alpha-Beta error:', e);
    }
}

async function runCSP() {
    try {
        const response = await fetch('/api/ai/csp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const result = await response.json();
        showResult('csp-result', result);
        loadAlgorithmLog();
    } catch (e) {
        console.error('CSP error:', e);
    }
}