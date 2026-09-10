import os
import json
import random
import sqlite3
from datetime import datetime
from flask import Flask, render_template, jsonify, request, g
from threading import Thread
import time

app = Flask(__name__)
app.config['DATABASE'] = os.path.join(app.root_path, 'sentinel_ai.db')

simulation_state = {
    'running': False,
    'current_attack': None,
    'attack_stage': 0,
    'attack_stages': [
        'Attack Started',
        'Initial Device Compromised',
        'Suspicious Activity Detected',
        'Network Investigation',
        'Possible Propagation',
        'Risk Assessment',
        'Defensive Decision',
        'Threat Contained'
    ],
    'compromised_devices': set(),
    'isolated_devices': set(),
    'events': [],
    'lock': __import__('threading').Lock()
}

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Create tables if they don't exist (no external schema.sql required)."""
    db = sqlite3.connect(app.config['DATABASE'])
    db.executescript('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT DEFAULT 'healthy',
            vulnerability_score REAL DEFAULT 0.5,
            traffic_level REAL DEFAULT 20.0,
            cpu_usage REAL DEFAULT 10.0,
            criticality TEXT DEFAULT 'medium',
            compromise_probability REAL DEFAULT 0.0,
            isolated INTEGER DEFAULT 0,
            x REAL DEFAULT 0,
            y REAL DEFAULT 0,
            symptoms TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source INTEGER NOT NULL,
            target INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT NOT NULL,
            source_device INTEGER,
            target_device INTEGER,
            severity TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'active',
            start_time TEXT,
            current_stage TEXT,
            event_history TEXT DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id INTEGER,
            event_type TEXT NOT NULL,
            description TEXT,
            timestamp TEXT
        );
    ''')
    db.commit()
    db.close()
    print("Database initialized successfully!")

class AIAlgorithms:
    @staticmethod
    def bfs(graph, start):
        visited = []
        queue = [start]
        levels = {start: 0}
        parent = {start: None}
        while queue:
            node = queue.pop(0)
            if node not in visited:
                visited.append(node)
                for neighbor in graph.get(node, []):
                    if neighbor not in visited and neighbor not in queue:
                        queue.append(neighbor)
                        levels[neighbor] = levels[node] + 1
                        parent[neighbor] = node
        return {
            'visited': visited,
            'levels': levels,
            'parent': parent,
            'max_depth': max(levels.values()) if levels else 0
        }

    @staticmethod
    def dfs(graph, start, visited=None):
        if visited is None:
            visited = []
        visited.append(start)
        for neighbor in graph.get(start, []):
            if neighbor not in visited:
                AIAlgorithms.dfs(graph, neighbor, visited)
        return visited

    @staticmethod
    def depth_limited_search(graph, start, limit):
        def dls(node, depth, visited, path):
            visited.append(node)
            path.append(node)
            if depth >= limit:
                return visited, path
            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    dls(neighbor, depth + 1, visited, path)
            return visited, path
        visited, path = dls(start, 0, [], [])
        return {'visited': visited, 'path': path, 'limit': limit}

    @staticmethod
    def iterative_deepening_search(graph, start, max_depth=10):
        for depth in range(max_depth + 1):
            result = AIAlgorithms.depth_limited_search(graph, start, depth)
            if result['visited']:
                return {
                    'visited': result['visited'],
                    'path': result['path'],
                    'final_depth': depth,
                    'iterations': depth + 1
                }
        return {'visited': [], 'path': [], 'final_depth': max_depth, 'iterations': max_depth + 1}

    @staticmethod
    def astar(graph, start, goal, heuristic=None):
        if heuristic is None:
            heuristic = lambda n: 0
        open_set = [start]
        came_from = {}
        g_score = {start: 0}
        f_score = {start: heuristic(start)}
        visited_order = []
        while open_set:
            current = min(open_set, key=lambda n: f_score.get(n, float('inf')))
            visited_order.append(current)
            if current == goal:
                path = []
                while current in came_from:
                    path.append(current)
                    current = came_from[current]
                path.append(start)
                path.reverse()
                return {
                    'path': path,
                    'cost': g_score[goal],
                    'visited': visited_order,
                    'nodes_expanded': len(visited_order)
                }
            open_set.remove(current)
            for neighbor in graph.get(current, []):
                tentative_g = g_score[current] + 1
                if tentative_g < g_score.get(neighbor, float('inf')):
                    came_from[neighbor] = current
                    g_score[neighbor] = tentative_g
                    f_score[neighbor] = tentative_g + heuristic(neighbor)
                    if neighbor not in open_set:
                        open_set.append(neighbor)
        return {'path': [], 'cost': float('inf'), 'visited': visited_order, 'nodes_expanded': len(visited_order)}

    @staticmethod
    def bayesian_compromise_probability(symptoms, prior=0.1):
        likelihood_ratios = {
            'high_cpu': 3.0,
            'high_traffic': 2.5,
            'failed_logins': 4.0,
            'unusual_ports': 3.5,
            'file_changes': 5.0,
            'network_scans': 4.5
        }
        posterior_odds = prior / (1 - prior)
        active_symptoms = []
        for symptom, present in symptoms.items():
            if present and symptom in likelihood_ratios:
                posterior_odds *= likelihood_ratios[symptom]
                active_symptoms.append(symptom)
        posterior_prob = posterior_odds / (1 + posterior_odds)
        return {
            'prior_probability': prior,
            'posterior_probability': min(posterior_prob, 0.99),
            'active_symptoms': active_symptoms,
            'likelihood_contributions': {s: likelihood_ratios[s] for s in active_symptoms}
        }

    @staticmethod
    def alpha_beta_pruning(state, depth, alpha, beta, maximizing_player, evaluate_func, get_moves_func):
        if depth == 0:
            return evaluate_func(state), None
        moves = get_moves_func(state)
        if not moves:
            return evaluate_func(state), None
        best_move = None
        if maximizing_player:
            max_eval = float('-inf')
            for move in moves:
                new_state = move['apply'](state)
                eval_score, _ = AIAlgorithms.alpha_beta_pruning(
                    new_state, depth - 1, alpha, beta, False, evaluate_func, get_moves_func
                )
                if eval_score > max_eval:
                    max_eval = eval_score
                    best_move = move
                alpha = max(alpha, eval_score)
                if beta <= alpha:
                    break
            return max_eval, best_move
        else:
            min_eval = float('inf')
            for move in moves:
                new_state = move['apply'](state)
                eval_score, _ = AIAlgorithms.alpha_beta_pruning(
                    new_state, depth - 1, alpha, beta, True, evaluate_func, get_moves_func
                )
                if eval_score < min_eval:
                    min_eval = eval_score
                    best_move = move
                beta = min(beta, eval_score)
                if beta <= alpha:
                    break
            return min_eval, best_move

    @staticmethod
    def constraint_satisfaction_firewall(rules, constraints):
        assignment = {}
        unassigned = list(rules.keys())
        def is_consistent(var, value, assignment):
            for constraint in constraints:
                if var in constraint['vars']:
                    involved = [v for v in constraint['vars'] if v in assignment or v == var]
                    if len(involved) == len(constraint['vars']):
                        values = {v: assignment.get(v, value) for v in constraint['vars']}
                        if not constraint['check'](values):
                            return False
            return True
        def backtrack(assignment, unassigned):
            if not unassigned:
                return assignment
            var = unassigned[0]
            for value in ['allow', 'block']:
                if is_consistent(var, value, assignment):
                    assignment[var] = value
                    result = backtrack(assignment, unassigned[1:])
                    if result is not None:
                        return result
                    del assignment[var]
            return None
        return backtrack(assignment, unassigned)

class SimulationEngine:
    ATTACK_TYPES = {
        'malware_propagation': {
            'name': 'Malware Propagation',
            'spread_rate': 0.3,
            'severity': 'high',
            'stages': ['Infection', 'Replication', 'Lateral Movement', 'Data Exfiltration']
        },
        'ransomware': {
            'name': 'Ransomware Simulation',
            'spread_rate': 0.2,
            'severity': 'critical',
            'stages': ['Initial Access', 'Encryption', 'Ransom Demand', 'Spread']
        },
        'ddos': {
            'name': 'DDoS Simulation',
            'spread_rate': 0.0,
            'severity': 'high',
            'stages': ['Reconnaissance', 'Botnet Activation', 'Traffic Flood', 'Service Degradation']
        },
        'insider_threat': {
            'name': 'Insider Threat',
            'spread_rate': 0.15,
            'severity': 'medium',
            'stages': ['Privilege Escalation', 'Data Access', 'Exfiltration', 'Cover-up']
        },
        'phishing': {
            'name': 'Phishing-Based Compromise',
            'spread_rate': 0.25,
            'severity': 'medium',
            'stages': ['Email Delivery', 'Credential Harvest', 'Account Compromise', 'Lateral Movement']
        }
    }

    @staticmethod
    def generate_ip():
        return "192.168.{}.{}".format(random.randint(0, 255), random.randint(1, 254))

    @staticmethod
    def create_device(name, device_type, x=0, y=0):
        vulnerability = round(random.uniform(0.1, 0.9), 2)
        criticality = random.choice(['low', 'medium', 'high', 'critical'])
        return {
            'name': name,
            'type': device_type,
            'ip_address': SimulationEngine.generate_ip(),
            'status': 'healthy',
            'vulnerability_score': vulnerability,
            'traffic_level': round(random.uniform(10, 50), 1),
            'cpu_usage': round(random.uniform(5, 30), 1),
            'criticality': criticality,
            'compromise_probability': 0.0,
            'isolated': False,
            'x': x,
            'y': y,
            'symptoms': {
                'high_cpu': False,
                'high_traffic': False,
                'failed_logins': False,
                'unusual_ports': False,
                'file_changes': False,
                'network_scans': False
            }
        }

    @staticmethod
    def propagate_attack(devices, connections, attack_type, source_id, compromised_set):
        attack_info = SimulationEngine.ATTACK_TYPES[attack_type]
        new_compromised = set()
        graph = {d['id']: [] for d in devices}
        for conn in connections:
            if conn['source'] in graph and conn['target'] in graph:
                graph[conn['source']].append(conn['target'])
                graph[conn['target']].append(conn['source'])
        for compromised_id in compromised_set:
            if compromised_id not in graph:
                continue
            for neighbor_id in graph[compromised_id]:
                if neighbor_id not in compromised_set:
                    neighbor = next((d for d in devices if d['id'] == neighbor_id), None)
                    if neighbor and not neighbor['isolated']:
                        spread_chance = attack_info['spread_rate'] * neighbor['vulnerability_score']
                        if random.random() < spread_chance:
                            new_compromised.add(neighbor_id)
        return new_compromised

    @staticmethod
    def apply_attack_effects(device, attack_type):
        if attack_type == 'ddos':
            device['traffic_level'] = min(100, device['traffic_level'] + random.uniform(30, 60))
            device['cpu_usage'] = min(100, device['cpu_usage'] + random.uniform(20, 40))
            device['symptoms']['high_traffic'] = True
            device['symptoms']['high_cpu'] = True
        elif attack_type == 'ransomware':
            device['cpu_usage'] = min(100, device['cpu_usage'] + random.uniform(40, 70))
            device['symptoms']['high_cpu'] = True
            device['symptoms']['file_changes'] = True
        elif attack_type == 'malware_propagation':
            device['traffic_level'] = min(100, device['traffic_level'] + random.uniform(10, 30))
            device['cpu_usage'] = min(100, device['cpu_usage'] + random.uniform(10, 25))
            device['symptoms']['network_scans'] = True
            device['symptoms']['high_traffic'] = True
        elif attack_type == 'insider_threat':
            device['symptoms']['failed_logins'] = True
            device['symptoms']['file_changes'] = True
        elif attack_type == 'phishing':
            device['symptoms']['failed_logins'] = True
            device['symptoms']['unusual_ports'] = True
        device['status'] = 'compromised'
        device['compromise_probability'] = round(random.uniform(0.7, 0.99), 2)
        return device

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/network-builder')
def network_builder():
    return render_template('network_builder.html')

@app.route('/attack-simulation')
def attack_simulation():
    return render_template('attack_simulation.html')

@app.route('/ai-analysis')
def ai_analysis():
    return render_template('ai_analysis.html')

@app.route('/api/devices', methods=['GET', 'POST'])
def devices():
    db = get_db()
    if request.method == 'POST':
        data = request.json
        cursor = db.execute(
            "INSERT INTO devices (name, type, ip_address, status, vulnerability_score, traffic_level, cpu_usage, criticality, compromise_probability, isolated, x, y) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (data['name'], data['type'], data.get('ip_address', SimulationEngine.generate_ip()),
             'healthy', data.get('vulnerability_score', 0.5), data.get('traffic_level', 20.0),
             data.get('cpu_usage', 10.0), data.get('criticality', 'medium'), 0.0, False,
             data.get('x', 0), data.get('y', 0))
        )
        db.commit()
        return jsonify({'id': cursor.lastrowid, 'status': 'created'})
    rows = db.execute('SELECT * FROM devices').fetchall()
    devices_list = [dict(row) for row in rows]
    for d in devices_list:
        d['symptoms'] = json.loads(d.get('symptoms', '{}') or '{}')
    return jsonify(devices_list)

@app.route('/api/devices/<int:device_id>', methods=['PUT', 'DELETE'])
def device_detail(device_id):
    db = get_db()
    if request.method == 'DELETE':
        db.execute('DELETE FROM devices WHERE id = ?', (device_id,))
        db.execute('DELETE FROM connections WHERE source = ? OR target = ?', (device_id, device_id))
        db.commit()
        return jsonify({'status': 'deleted'})
    data = request.json
    db.execute(
        "UPDATE devices SET name = ?, type = ?, x = ?, y = ?, vulnerability_score = ?, criticality = ? WHERE id = ?",
        (data.get('name'), data.get('type'), data.get('x'), data.get('y'),
         data.get('vulnerability_score'), data.get('criticality'), device_id)
    )
    db.commit()
    return jsonify({'status': 'updated'})

@app.route('/api/connections', methods=['GET', 'POST'])
def connections():
    db = get_db()
    if request.method == 'POST':
        data = request.json
        cursor = db.execute(
            'INSERT INTO connections (source, target) VALUES (?, ?)',
            (data['source'], data['target'])
        )
        db.commit()
        return jsonify({'id': cursor.lastrowid, 'status': 'created'})
    rows = db.execute('SELECT * FROM connections').fetchall()
    return jsonify([dict(row) for row in rows])

@app.route('/api/connections/<int:conn_id>', methods=['DELETE'])
def delete_connection(conn_id):
    db = get_db()
    db.execute('DELETE FROM connections WHERE id = ?', (conn_id,))
    db.commit()
    return jsonify({'status': 'deleted'})

@app.route('/api/dashboard-stats')
def dashboard_stats():
    db = get_db()
    total = db.execute('SELECT COUNT(*) as count FROM devices').fetchone()['count']
    healthy = db.execute("SELECT COUNT(*) as count FROM devices WHERE status = 'healthy'").fetchone()['count']
    compromised = db.execute("SELECT COUNT(*) as count FROM devices WHERE status = 'compromised'").fetchone()['count']
    suspicious = db.execute("SELECT COUNT(*) as count FROM devices WHERE status = 'suspicious'").fetchone()['count']
    isolated = db.execute("SELECT COUNT(*) as count FROM devices WHERE isolated = 1").fetchone()['count']
    risk_score = 0
    if total > 0:
        risk_score = round((compromised * 40 + suspicious * 20 + isolated * 10) / total, 1)
    threat_level = 'Low'
    if compromised > 0:
        threat_level = 'Critical' if compromised > total * 0.3 else 'High'
    elif suspicious > 0:
        threat_level = 'Medium'
    with simulation_state['lock']:
        current_attack = simulation_state['current_attack']
    return jsonify({
        'total_devices': total,
        'healthy_devices': healthy,
        'suspicious_devices': suspicious,
        'compromised_devices': compromised,
        'isolated_devices': isolated,
        'threat_level': threat_level,
        'risk_score': min(100, risk_score),
        'active_attack': current_attack,
        'ai_recommendation': generate_ai_recommendation(compromised, suspicious, total)
    })

def generate_ai_recommendation(compromised, suspicious, total):
    if compromised == 0 and suspicious == 0:
        return "Network appears secure. Continue monitoring."
    elif compromised > total * 0.3:
        return "CRITICAL: Mass compromise detected. Isolate affected segments immediately. Run full network scan."
    elif compromised > 0:
        return "High threat detected. Isolate compromised devices. Investigate attack vector using DFS tracing."
    elif suspicious > 0:
        return "Suspicious activity detected. Run BFS network discovery and Bayesian analysis on affected nodes."
    return "Monitor network traffic for anomalies."

@app.route('/api/events')
def get_events():
    db = get_db()
    rows = db.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT 50').fetchall()
    return jsonify([dict(row) for row in rows])

@app.route('/api/attacks', methods=['GET', 'POST'])
def attacks():
    db = get_db()
    if request.method == 'POST':
        data = request.json
        cursor = db.execute(
            "INSERT INTO attacks (attack_type, source_device, target_device, severity, status, start_time, current_stage, event_history) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (data['attack_type'], data.get('source_device'), data.get('target_device'),
             data.get('severity', 'medium'), 'active', datetime.now().isoformat(),
             'Attack Started', json.dumps([{'stage': 'Attack Started', 'time': datetime.now().isoformat()}]))
        )
        db.commit()
        return jsonify({'id': cursor.lastrowid, 'status': 'created'})
    rows = db.execute('SELECT * FROM attacks ORDER BY start_time DESC').fetchall()
    attacks_list = []
    for row in rows:
        attack = dict(row)
        attack['event_history'] = json.loads(attack.get('event_history', '[]') or '[]')
        attacks_list.append(attack)
    return jsonify(attacks_list)

@app.route('/api/start-attack', methods=['POST'])
def start_attack():
    data = request.json
    attack_type = data['attack_type']
    source_id = data.get('source_device')
    target_id = data.get('target_device')
    db = get_db()
    cursor = db.execute(
        "INSERT INTO attacks (attack_type, source_device, target_device, severity, status, start_time, current_stage, event_history) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (attack_type, source_id, target_id,
         SimulationEngine.ATTACK_TYPES[attack_type]['severity'],
         'active', datetime.now().isoformat(),
         'Attack Started', json.dumps([{'stage': 'Attack Started', 'time': datetime.now().isoformat()}]))
    )
    attack_id = cursor.lastrowid
    if source_id:
        db.execute("UPDATE devices SET status = 'compromised' WHERE id = ?", (source_id,))
        db.execute("UPDATE devices SET symptoms = ? WHERE id = ?",
                   (json.dumps({'high_cpu': True, 'high_traffic': True}), source_id))
    db.commit()
    with simulation_state['lock']:
        simulation_state['running'] = True
        simulation_state['current_attack'] = {
            'id': attack_id,
            'type': attack_type,
            'source': source_id,
            'target': target_id,
            'stage_index': 0
        }
        if source_id:
            simulation_state['compromised_devices'] = {source_id}
    thread = Thread(target=run_attack_simulation, args=(attack_id, attack_type, source_id))
    thread.daemon = True
    thread.start()
    return jsonify({'status': 'started', 'attack_id': attack_id})

@app.route('/api/stop-attack', methods=['POST'])
def stop_attack():
    with simulation_state['lock']:
        simulation_state['running'] = False
        simulation_state['current_attack'] = None
        simulation_state['compromised_devices'] = set()
    db = get_db()
    db.execute("UPDATE attacks SET status = 'stopped' WHERE status = 'active'")
    db.commit()
    return jsonify({'status': 'stopped'})

@app.route('/api/reset-network', methods=['POST'])
def reset_network():
    db = get_db()
    db.execute("UPDATE devices SET status = 'healthy', compromise_probability = 0, isolated = 0, traffic_level = 20, cpu_usage = 10")
    db.execute("UPDATE devices SET symptoms = '{}' ")
    db.execute("UPDATE attacks SET status = 'stopped' WHERE status = 'active'")
    db.commit()
    with simulation_state['lock']:
        simulation_state['running'] = False
        simulation_state['current_attack'] = None
        simulation_state['compromised_devices'] = set()
        simulation_state['isolated_devices'] = set()
        simulation_state['events'] = []
    return jsonify({'status': 'reset'})

@app.route('/api/isolate-device/<int:device_id>', methods=['POST'])
def isolate_device(device_id):
    db = get_db()
    db.execute("UPDATE devices SET isolated = 1, status = CASE WHEN status = 'compromised' THEN 'isolated' ELSE status END WHERE id = ?", (device_id,))
    db.commit()
    with simulation_state['lock']:
        simulation_state['isolated_devices'].add(device_id)
    return jsonify({'status': 'isolated'})

@app.route('/api/restore-device/<int:device_id>', methods=['POST'])
def restore_device(device_id):
    db = get_db()
    db.execute("UPDATE devices SET isolated = 0, status = 'healthy', compromise_probability = 0, symptoms = '{}' WHERE id = ?", (device_id,))
    db.commit()
    with simulation_state['lock']:
        simulation_state['isolated_devices'].discard(device_id)
        simulation_state['compromised_devices'].discard(device_id)
    return jsonify({'status': 'restored'})

@app.route('/api/ai/bfs', methods=['POST'])
def run_bfs():
    data = request.json
    start_id = data.get('start_node')
    db = get_db()
    connections_rows = db.execute('SELECT source, target FROM connections').fetchall()
    graph = {}
    for conn in connections_rows:
        if conn['source'] not in graph:
            graph[conn['source']] = []
        if conn['target'] not in graph:
            graph[conn['target']] = []
        graph[conn['source']].append(conn['target'])
        graph[conn['target']].append(conn['source'])
    result = AIAlgorithms.bfs(graph, start_id)
    db.execute(
        'INSERT INTO events (event_type, description, timestamp) VALUES (?, ?, ?)',
        ('AI_BFS', "BFS from node {}: visited {} nodes, max depth {}".format(start_id, len(result['visited']), result['max_depth']),
         datetime.now().isoformat())
    )
    db.commit()
    return jsonify(result)

@app.route('/api/ai/dfs', methods=['POST'])
def run_dfs():
    data = request.json
    start_id = data.get('start_node')
    db = get_db()
    connections_rows = db.execute('SELECT source, target FROM connections').fetchall()
    graph = {}
    for conn in connections_rows:
        if conn['source'] not in graph:
            graph[conn['source']] = []
        if conn['target'] not in graph:
            graph[conn['target']] = []
        graph[conn['source']].append(conn['target'])
        graph[conn['target']].append(conn['source'])
    result = AIAlgorithms.dfs(graph, start_id)
    db.execute(
        'INSERT INTO events (event_type, description, timestamp) VALUES (?, ?, ?)',
        ('AI_DFS', "DFS from node {}: visited {} nodes".format(start_id, len(result)),
         datetime.now().isoformat())
    )
    db.commit()
    return jsonify({'visited': result, 'path': result, 'nodes_investigated': len(result)})

@app.route('/api/ai/dls', methods=['POST'])
def run_dls():
    data = request.json
    start_id = data.get('start_node')
    limit = data.get('limit', 3)
    db = get_db()
    connections_rows = db.execute('SELECT source, target FROM connections').fetchall()
    graph = {}
    for conn in connections_rows:
        if conn['source'] not in graph:
            graph[conn['source']] = []
        if conn['target'] not in graph:
            graph[conn['target']] = []
        graph[conn['source']].append(conn['target'])
        graph[conn['target']].append(conn['source'])
    result = AIAlgorithms.depth_limited_search(graph, start_id, limit)
    db.execute(
        'INSERT INTO events (event_type, description, timestamp) VALUES (?, ?, ?)',
        ('AI_DLS', "DLS from node {} with limit {}: visited {} nodes".format(start_id, limit, len(result['visited'])),
         datetime.now().isoformat())
    )
    db.commit()
    return jsonify(result)

@app.route('/api/ai/ids', methods=['POST'])
def run_ids():
    data = request.json
    start_id = data.get('start_node')
    max_depth = data.get('max_depth', 5)
    db = get_db()
    connections_rows = db.execute('SELECT source, target FROM connections').fetchall()
    graph = {}
    for conn in connections_rows:
        if conn['source'] not in graph:
            graph[conn['source']] = []
        if conn['target'] not in graph:
            graph[conn['target']] = []
        graph[conn['source']].append(conn['target'])
        graph[conn['target']].append(conn['source'])
    result = AIAlgorithms.iterative_deepening_search(graph, start_id, max_depth)
    db.execute(
        'INSERT INTO events (event_type, description, timestamp) VALUES (?, ?, ?)',
        ('AI_IDS', "IDS from node {}: reached depth {} in {} iterations".format(start_id, result['final_depth'], result['iterations']),
         datetime.now().isoformat())
    )
    db.commit()
    return jsonify(result)

@app.route('/api/ai/astar', methods=['POST'])
def run_astar():
    data = request.json
    start_id = data.get('start_node')
    goal_id = data.get('goal_node')
    db = get_db()
    devices_rows = db.execute('SELECT id, x, y FROM devices').fetchall()
    positions = {row['id']: (row['x'], row['y']) for row in devices_rows}
    connections_rows = db.execute('SELECT source, target FROM connections').fetchall()
    graph = {}
    for conn in connections_rows:
        if conn['source'] not in graph:
            graph[conn['source']] = []
        if conn['target'] not in graph:
            graph[conn['target']] = []
        graph[conn['source']].append(conn['target'])
        graph[conn['target']].append(conn['source'])
    def heuristic(node):
        if node in positions and goal_id in positions:
            dx = positions[node][0] - positions[goal_id][0]
            dy = positions[node][1] - positions[goal_id][1]
            return (dx**2 + dy**2) ** 0.5
        return 0
    result = AIAlgorithms.astar(graph, start_id, goal_id, heuristic)
    db.execute(
        'INSERT INTO events (event_type, description, timestamp) VALUES (?, ?, ?)',
        ('AI_ASTAR', "A* from {} to {}: path length {}, cost {}".format(start_id, goal_id, len(result['path']), result['cost']),
         datetime.now().isoformat())
    )
    db.commit()
    return jsonify(result)

@app.route('/api/ai/bayesian', methods=['POST'])
def run_bayesian():
    data = request.json
    device_id = data.get('device_id')
    db = get_db()
    device = db.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    symptoms = json.loads(device['symptoms'] or '{}')
    if not symptoms:
        symptoms = {
            'high_cpu': device['cpu_usage'] > 70,
            'high_traffic': device['traffic_level'] > 70,
            'failed_logins': device['status'] == 'compromised',
            'unusual_ports': device['status'] == 'compromised',
            'file_changes': device['status'] == 'compromised',
            'network_scans': device['traffic_level'] > 60
        }
    prior = device['vulnerability_score']
    result = AIAlgorithms.bayesian_compromise_probability(symptoms, prior)
    db.execute(
        'INSERT INTO events (event_type, description, timestamp) VALUES (?, ?, ?)',
        ('AI_BAYESIAN', "Bayesian analysis on device {}: compromise probability {:.2%}".format(device_id, result['posterior_probability']),
         datetime.now().isoformat())
    )
    db.commit()
    return jsonify(result)

@app.route('/api/ai/alphabeta', methods=['POST'])
def run_alphabeta():
    db = get_db()
    total = db.execute('SELECT COUNT(*) as count FROM devices').fetchone()['count']
    compromised = db.execute("SELECT COUNT(*) as count FROM devices WHERE status = 'compromised'").fetchone()['count']
    suspicious = db.execute("SELECT COUNT(*) as count FROM devices WHERE status = 'suspicious'").fetchone()['count']
    isolated = db.execute("SELECT COUNT(*) as count FROM devices WHERE isolated = 1").fetchone()['count']
    initial_state = {
        'compromised': compromised,
        'suspicious': suspicious,
        'isolated': isolated,
        'total': total
    }
    def evaluate(state):
        score = 100
        score -= state['compromised'] * 20
        score -= state['suspicious'] * 10
        score += state['isolated'] * 5
        return score
    def get_moves(state):
        moves = []
        if state['compromised'] > 0:
            moves.append({
                'name': 'Isolate Compromised',
                'apply': lambda s: {**s, 'compromised': max(0, s['compromised'] - 1), 'isolated': s['isolated'] + 1}
            })
        if state['suspicious'] > 0:
            moves.append({
                'name': 'Investigate Suspicious',
                'apply': lambda s: {**s, 'suspicious': max(0, s['suspicious'] - 1)}
            })
        moves.append({
            'name': 'Monitor',
            'apply': lambda s: s
        })
        return moves
    score, best_move = AIAlgorithms.alpha_beta_pruning(
        initial_state, 3, float('-inf'), float('inf'), True, evaluate, get_moves
    )
    result = {
        'optimal_score': score,
        'recommended_action': best_move['name'] if best_move else 'Monitor',
        'state_evaluated': evaluate(initial_state),
        'depth': 3
    }
    db.execute(
        'INSERT INTO events (event_type, description, timestamp) VALUES (?, ?, ?)',
        ('AI_ALPHABETA', "Alpha-Beta pruning recommends: {} (score: {})".format(result['recommended_action'], score),
         datetime.now().isoformat())
    )
    db.commit()
    return jsonify(result)

@app.route('/api/ai/csp', methods=['POST'])
def run_csp():
    rules = {
        'http': 'allow',
        'https': 'allow',
        'ssh': 'allow',
        'ftp': 'block',
        'telnet': 'block',
        'smtp': 'allow'
    }
    constraints = [
        {
            'vars': ['ssh', 'telnet'],
            'check': lambda vals: not (vals.get('ssh') == 'allow' and vals.get('telnet') == 'allow')
        },
        {
            'vars': ['ftp', 'http'],
            'check': lambda vals: not (vals.get('ftp') == 'allow' and vals.get('http') == 'block')
        },
        {
            'vars': ['https'],
            'check': lambda vals: vals.get('https') == 'allow'
        }
    ]
    result = AIAlgorithms.constraint_satisfaction_firewall(rules, constraints)
    db = get_db()
    db.execute(
        'INSERT INTO events (event_type, description, timestamp) VALUES (?, ?, ?)',
        ('AI_CSP', "CSP firewall optimization: {} rules configured".format(len(result)),
         datetime.now().isoformat())
    )
    db.commit()
    return jsonify({'optimized_rules': result, 'constraints_satisfied': len(constraints)})

def run_attack_simulation(attack_id, attack_type, source_id):
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    stages = simulation_state['attack_stages']
    for i in range(1, len(stages)):
        time.sleep(4)
        with simulation_state['lock']:
            if not simulation_state['running']:
                break
            simulation_state['current_attack']['stage_index'] = i
        db.execute(
            "UPDATE attacks SET current_stage = ? WHERE id = ?",
            (stages[i], attack_id)
        )
        attack = db.execute('SELECT * FROM attacks WHERE id = ?', (attack_id,)).fetchone()
        if attack:
            history = json.loads(attack['event_history'] or '[]')
            history.append({'stage': stages[i], 'time': datetime.now().isoformat()})
            db.execute('UPDATE attacks SET event_history = ? WHERE id = ?', (json.dumps(history), attack_id))
        db.execute(
            'INSERT INTO events (attack_id, event_type, description, timestamp) VALUES (?, ?, ?, ?)',
            (attack_id, 'ATTACK_STAGE', "Attack {} reached stage: {}".format(attack_id, stages[i]), datetime.now().isoformat())
        )
        if i >= 3 and attack_type != 'ddos':
            devices = db.execute('SELECT * FROM devices').fetchall()
            connections = db.execute('SELECT * FROM connections').fetchall()
            devices_list = [dict(d) for d in devices]
            connections_list = [dict(c) for c in connections]
            with simulation_state['lock']:
                compromised = set(simulation_state['compromised_devices'])
            new_compromised = SimulationEngine.propagate_attack(
                devices_list, connections_list, attack_type, source_id, compromised
            )
            for device_id in new_compromised:
                db.execute("UPDATE devices SET status = 'compromised' WHERE id = ?", (device_id,))
                device = next((d for d in devices_list if d['id'] == device_id), None)
                if device:
                    SimulationEngine.apply_attack_effects(device, attack_type)
                    db.execute(
                        'UPDATE devices SET traffic_level = ?, cpu_usage = ?, symptoms = ? WHERE id = ?',
                        (device['traffic_level'], device['cpu_usage'], json.dumps(device['symptoms']), device_id)
                    )
            with simulation_state['lock']:
                simulation_state['compromised_devices'].update(new_compromised)
            if new_compromised:
                db.execute(
                    'INSERT INTO events (attack_id, event_type, description, timestamp) VALUES (?, ?, ?, ?)',
                    (attack_id, 'ATTACK_PROPAGATION',
                     "Attack propagated to {} new devices".format(len(new_compromised)), datetime.now().isoformat())
                )
        if attack_type == 'ddos':
            attack = db.execute('SELECT * FROM attacks WHERE id = ?', (attack_id,)).fetchone()
            if attack and attack['target_device']:
                target = db.execute('SELECT * FROM devices WHERE id = ?', (attack['target_device'],)).fetchone()
                if target:
                    new_traffic = min(100, target['traffic_level'] + random.uniform(15, 35))
                    new_cpu = min(100, target['cpu_usage'] + random.uniform(10, 25))
                    db.execute(
                        'UPDATE devices SET traffic_level = ?, cpu_usage = ?, status = ? WHERE id = ?',
                        (new_traffic, new_cpu, 'compromised', attack['target_device'])
                    )
        db.commit()
    db.execute("UPDATE attacks SET status = 'completed', current_stage = 'Threat Contained' WHERE id = ?", (attack_id,))
    db.commit()
    with simulation_state['lock']:
        simulation_state['running'] = False
    db.close()

@app.route('/api/seed-network', methods=['POST'])
def seed_network():
    db = get_db()
    db.execute('DELETE FROM connections')
    db.execute('DELETE FROM devices')
    db.execute('DELETE FROM attacks')
    db.execute('DELETE FROM events')
    db.commit()
    sample_devices = [
        ('Router-01', 'Router', 400, 300),
        ('Firewall-01', 'Firewall', 400, 200),
        ('Server-01', 'Server', 300, 400),
        ('Server-02', 'Server', 500, 400),
        ('DB-01', 'Database', 300, 500),
        ('DB-02', 'Database', 500, 500),
        ('WS-01', 'Workstation', 200, 300),
        ('WS-02', 'Workstation', 600, 300),
        ('WS-03', 'Workstation', 200, 400),
        ('Laptop-01', 'Laptop', 600, 400),
        ('IoT-01', 'IoT Device', 350, 100),
        ('IoT-02', 'IoT Device', 450, 100),
    ]
    device_ids = []
    for name, dtype, x, y in sample_devices:
        device = SimulationEngine.create_device(name, dtype, x, y)
        cursor = db.execute(
            "INSERT INTO devices (name, type, ip_address, status, vulnerability_score, traffic_level, cpu_usage, criticality, compromise_probability, isolated, x, y, symptoms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (device['name'], device['type'], device['ip_address'], device['status'],
             device['vulnerability_score'], device['traffic_level'], device['cpu_usage'],
             device['criticality'], device['compromise_probability'], device['isolated'],
             device['x'], device['y'], json.dumps(device['symptoms']))
        )
        device_ids.append(cursor.lastrowid)
    db.commit()
    connections_data = [
        (device_ids[0], device_ids[1]),
        (device_ids[0], device_ids[2]),
        (device_ids[0], device_ids[3]),
        (device_ids[2], device_ids[4]),
        (device_ids[3], device_ids[5]),
        (device_ids[0], device_ids[6]),
        (device_ids[0], device_ids[7]),
        (device_ids[0], device_ids[8]),
        (device_ids[0], device_ids[9]),
        (device_ids[1], device_ids[10]),
        (device_ids[1], device_ids[11]),
        (device_ids[2], device_ids[3]),
        (device_ids[6], device_ids[8]),
    ]
    for src, tgt in connections_data:
        db.execute('INSERT INTO connections (source, target) VALUES (?, ?)', (src, tgt))
    db.commit()
    return jsonify({'status': 'seeded', 'devices': len(device_ids), 'connections': len(connections_data)})

if __name__ == '__main__':
    init_db()  # Always ensure tables exist
    app.run(debug=True, host='0.0.0.0', port=5000)
    