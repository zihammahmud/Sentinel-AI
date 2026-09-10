DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS connections;
DROP TABLE IF EXISTS attacks;
DROP TABLE IF EXISTS events;

CREATE TABLE devices (
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

CREATE TABLE connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source INTEGER NOT NULL,
    target INTEGER NOT NULL,
    FOREIGN KEY (source) REFERENCES devices(id),
    FOREIGN KEY (target) REFERENCES devices(id)
);

CREATE TABLE attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT NOT NULL,
    source_device INTEGER,
    target_device INTEGER,
    severity TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'active',
    start_time TEXT,
    current_stage TEXT,
    event_history TEXT DEFAULT '[]',
    FOREIGN KEY (source_device) REFERENCES devices(id),
    FOREIGN KEY (target_device) REFERENCES devices(id)
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_id INTEGER,
    event_type TEXT NOT NULL,
    description TEXT,
    timestamp TEXT,
    FOREIGN KEY (attack_id) REFERENCES attacks(id)
);