let builderCy = null;
let selectedNode = null;
let devices = [];
let connections = [];

const deviceColors = {
    'Workstation': '#3b82f6',
    'Laptop': '#8b5cf6',
    'Server': '#10b981',
    'Database': '#f59e0b',
    'Router': '#06b6d4',
    'Firewall': '#ef4444',
    'IoT Device': '#ec4899'
};

document.addEventListener('DOMContentLoaded', function() {
    initBuilderGraph();
    loadDevices();
    loadConnections();

    document.getElementById('device-vuln').addEventListener('input', function() {
        document.getElementById('vuln-display').textContent = this.value;
    });

    document.getElementById('add-device-form').addEventListener('submit', addDevice);
    document.getElementById('connect-form').addEventListener('submit', createConnection);
});

function initBuilderGraph() {
    builderCy = cytoscape({
        container: document.getElementById('network-builder-graph'),
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
                    'width': 50,
                    'height': 50,
                    'border-width': 2,
                    'border-color': '#1f2937'
                }
            },
            {
                selector: 'node:selected',
                style: {
                    'border-width': 4,
                    'border-color': '#10b981'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#374151',
                    'target-arrow-color': '#374151',
                    'target-arrow-shape': 'triangle',
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
                selector: '.isolated',
                style: {
                    'background-color': '#8b5cf6',
                    'border-color': '#7c3aed',
                    'border-width': 3,
                    'border-style': 'dashed'
                }
            }
        ],
        layout: { name: 'cose', padding: 20 },
        minZoom: 0.3,
        maxZoom: 3
    });

    builderCy.on('tap', 'node', function(evt) {
        selectedNode = evt.target;
    });

    builderCy.on('dbltap', 'node', function(evt) {
        const node = evt.target;
        openEditModal(node.data('deviceId'));
    });

    builderCy.on('cxttap', 'node', function(evt) {
        if (confirm('Delete this device?')) {
            deleteDevice(evt.target.data('deviceId'));
        }
    });

    builderCy.on('cxttap', 'edge', function(evt) {
        if (confirm('Delete this connection?')) {
            deleteConnection(evt.target.data('connId'));
        }
    });

    // Drag to create connection
    let sourceNode = null;
    builderCy.on('mousedown', 'node', function(evt) {
        if (evt.originalEvent.shiftKey) {
            sourceNode = evt.target;
        }
    });

    builderCy.on('mouseup', 'node', function(evt) {
        if (sourceNode && sourceNode.id() !== evt.target.id()) {
            createConnectionBetween(sourceNode.data('deviceId'), evt.target.data('deviceId'));
        }
        sourceNode = null;
    });
}

async function loadDevices() {
    try {
        const response = await fetch('/api/devices');
        devices = await response.json();
        updateDeviceSelects();
        updateDeviceTable();
        updateBuilderGraph();
    } catch (e) {
        console.error('Error loading devices:', e);
    }
}

async function loadConnections() {
    try {
        const response = await fetch('/api/connections');
        connections = await response.json();
        updateBuilderGraph();
    } catch (e) {
        console.error('Error loading connections:', e);
    }
}

function updateDeviceSelects() {
    const sourceSel = document.getElementById('conn-source');
    const targetSel = document.getElementById('conn-target');
    sourceSel.innerHTML = '';
    targetSel.innerHTML = '';

    devices.forEach(d => {
        const opt1 = document.createElement('option');
        opt1.value = d.id;
        opt1.textContent = d.name + ' (' + d.type + ')';
        sourceSel.appendChild(opt1);

        const opt2 = document.createElement('option');
        opt2.value = d.id;
        opt2.textContent = d.name + ' (' + d.type + ')';
        targetSel.appendChild(opt2);
    });
}

function updateDeviceTable() {
    const tbody = document.getElementById('device-table-body');
    tbody.innerHTML = devices.map(d => {
        const statusBadge = d.status === 'healthy' ? 'bg-success' : 
                           d.status === 'compromised' ? 'bg-danger' : 
                           d.status === 'suspicious' ? 'bg-warning' : 'bg-secondary';
        return `<tr>
            <td>${d.id}</td>
            <td>${d.name}</td>
            <td><span class="badge" style="background-color: ${deviceColors[d.type] || '#666'}">${d.type}</span></td>
            <td><code>${d.ip_address}</code></td>
            <td><span class="badge ${statusBadge}">${d.status}</span></td>
            <td>${d.vulnerability_score}</td>
            <td>${d.criticality}</td>
            <td>
                <button class="btn btn-sm btn-info" onclick="openEditModal(${d.id})">Edit</button>
                <button class="btn btn-sm btn-danger" onclick="deleteDevice(${d.id})">Delete</button>
            </td>
        </tr>`;
    }).join('');
}

function updateBuilderGraph() {
    builderCy.elements().remove();

    devices.forEach(d => {
        const color = deviceColors[d.type] || '#3b82f6';
        builderCy.add({
            group: 'nodes',
            data: {
                id: 'n' + d.id,
                label: d.name,
                deviceId: d.id,
                deviceType: d.type
            },
            position: { x: d.x || Math.random() * 700 + 50, y: d.y || Math.random() * 500 + 50 }
        });
        const node = builderCy.getElementById('n' + d.id);
        node.style('background-color', color);
        if (d.status === 'compromised') node.addClass('compromised');
        if (d.isolated) node.addClass('isolated');
    });

    connections.forEach(c => {
        builderCy.add({
            group: 'edges',
            data: {
                id: 'e' + c.id,
                source: 'n' + c.source,
                target: 'n' + c.target,
                connId: c.id
            }
        });
    });

    builderCy.layout({ name: 'cose', padding: 20, animate: true, animationDuration: 500 }).run();
}

async function addDevice(e) {
    e.preventDefault();
    const data = {
        name: document.getElementById('device-name').value,
        type: document.getElementById('device-type').value,
        vulnerability_score: parseFloat(document.getElementById('device-vuln').value),
        criticality: document.getElementById('device-criticality').value,
        x: Math.random() * 600 + 50,
        y: Math.random() * 400 + 50
    };

    try {
        await fetch('/api/devices', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        document.getElementById('add-device-form').reset();
        document.getElementById('vuln-display').textContent = '0.5';
        loadDevices();
    } catch (e) {
        console.error('Error adding device:', e);
    }
}

async function createConnection(e) {
    e.preventDefault();
    const source = document.getElementById('conn-source').value;
    const target = document.getElementById('conn-target').value;

    if (source === target) {
        alert('Cannot connect a device to itself');
        return;
    }

    try {
        await fetch('/api/connections', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source: parseInt(source), target: parseInt(target) })
        });
        loadConnections();
    } catch (e) {
        console.error('Error creating connection:', e);
    }
}

async function createConnectionBetween(sourceId, targetId) {
    try {
        await fetch('/api/connections', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source: sourceId, target: targetId })
        });
        loadConnections();
    } catch (e) {
        console.error('Error creating connection:', e);
    }
}

async function deleteDevice(deviceId) {
    try {
        await fetch('/api/devices/' + deviceId, { method: 'DELETE' });
        loadDevices();
        loadConnections();
    } catch (e) {
        console.error('Error deleting device:', e);
    }
}

async function deleteConnection(connId) {
    try {
        await fetch('/api/connections/' + connId, { method: 'DELETE' });
        loadConnections();
    } catch (e) {
        console.error('Error deleting connection:', e);
    }
}

function openEditModal(deviceId) {
    const device = devices.find(d => d.id === deviceId);
    if (!device) return;

    document.getElementById('edit-device-id').value = deviceId;
    document.getElementById('edit-name').value = device.name;
    document.getElementById('edit-type').value = device.type;
    document.getElementById('edit-vuln').value = device.vulnerability_score;
    document.getElementById('edit-criticality').value = device.criticality;

    new bootstrap.Modal(document.getElementById('editDeviceModal')).show();
}

async function saveDeviceEdit() {
    const deviceId = document.getElementById('edit-device-id').value;
    const data = {
        name: document.getElementById('edit-name').value,
        type: document.getElementById('edit-type').value,
        vulnerability_score: parseFloat(document.getElementById('edit-vuln').value),
        criticality: document.getElementById('edit-criticality').value
    };

    try {
        await fetch('/api/devices/' + deviceId, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        bootstrap.Modal.getInstance(document.getElementById('editDeviceModal')).hide();
        loadDevices();
    } catch (e) {
        console.error('Error updating device:', e);
    }
}

async function seedNetwork() {
    try {
        await fetch('/api/seed-network', { method: 'POST' });
        loadDevices();
        loadConnections();
    } catch (e) {
        console.error('Error seeding network:', e);
    }
}

async function resetNetwork() {
    try {
        await fetch('/api/reset-network', { method: 'POST' });
        loadDevices();
        loadConnections();
    } catch (e) {
        console.error('Error resetting network:', e);
    }
}

async function clearAllDevices() {
    if (!confirm('Clear all devices and connections?')) return;
    try {
        for (const d of devices) {
            await fetch('/api/devices/' + d.id, { method: 'DELETE' });
        }
        loadDevices();
        loadConnections();
    } catch (e) {
        console.error('Error clearing devices:', e);
    }
}
