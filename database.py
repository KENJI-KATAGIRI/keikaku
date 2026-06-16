import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "keikaku.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS offices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        office_name TEXT NOT NULL,
        email TEXT NOT NULL,
        pw_hash TEXT NOT NULL,
        pw_salt TEXT NOT NULL,
        plan TEXT DEFAULT 'trial',
        subscription_status TEXT DEFAULT 'trial',
        trial_end TEXT,
        jigyosho_no TEXT DEFAULT '',
        pref_no TEXT DEFAULT '',
        tanka_unit INTEGER DEFAULT 1100,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE TABLE IF NOT EXISTS counselors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        kana TEXT DEFAULT '',
        cert_acquired TEXT DEFAULT '',
        cert_next_renewal TEXT DEFAULT '',
        is_chief INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        counselor_id INTEGER,
        name TEXT NOT NULL,
        kana TEXT DEFAULT '',
        gender TEXT DEFAULT '',
        birthdate TEXT DEFAULT '',
        disability_type TEXT DEFAULT '',
        disability_level TEXT DEFAULT '',
        jukyusha_no TEXT DEFAULT '',
        jukyusha_valid_to TEXT DEFAULT '',
        address TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        family_name TEXT DEFAULT '',
        family_phone TEXT DEFAULT '',
        main_service TEXT DEFAULT '',
        contract_date TEXT DEFAULT '',
        monitoring_frequency TEXT DEFAULT '6months',
        next_monitoring_date TEXT DEFAULT '',
        last_monitoring_date TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id),
        FOREIGN KEY (counselor_id) REFERENCES counselors(id)
    );

    CREATE TABLE IF NOT EXISTS assessments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        client_id INTEGER NOT NULL,
        assess_date TEXT NOT NULL,
        living_situation TEXT DEFAULT '',
        daily_life TEXT DEFAULT '',
        family_support TEXT DEFAULT '',
        social_resources TEXT DEFAULT '',
        strengths TEXT DEFAULT '',
        challenges TEXT DEFAULT '',
        hopes TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id),
        FOREIGN KEY (client_id) REFERENCES clients(id)
    );

    CREATE TABLE IF NOT EXISTS service_plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        client_id INTEGER NOT NULL,
        plan_type TEXT DEFAULT 'draft',
        created_date TEXT NOT NULL,
        approved_date TEXT DEFAULT '',
        long_term_goal TEXT DEFAULT '',
        short_term_goal TEXT DEFAULT '',
        support_policy TEXT DEFAULT '',
        weekly_schedule TEXT DEFAULT '',
        services TEXT DEFAULT '[]',
        notes TEXT DEFAULT '',
        version INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id),
        FOREIGN KEY (client_id) REFERENCES clients(id)
    );

    CREATE TABLE IF NOT EXISTS monitoring_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        client_id INTEGER NOT NULL,
        monitor_date TEXT NOT NULL,
        visit_date TEXT DEFAULT '',
        counselor_id INTEGER,
        goal_achievement TEXT DEFAULT 'partial',
        satisfaction TEXT DEFAULT 'normal',
        service_status TEXT DEFAULT '',
        issues TEXT DEFAULT '',
        plan_change TEXT DEFAULT 'no_change',
        next_monitoring TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        submitted_to_city INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id),
        FOREIGN KEY (client_id) REFERENCES clients(id)
    );

    CREATE TABLE IF NOT EXISTS case_conferences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        client_id INTEGER NOT NULL,
        conference_date TEXT NOT NULL,
        location TEXT DEFAULT '',
        attendees TEXT DEFAULT '',
        agenda TEXT DEFAULT '',
        minutes TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id),
        FOREIGN KEY (client_id) REFERENCES clients(id)
    );

    CREATE TABLE IF NOT EXISTS consultation_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        client_id INTEGER,
        record_date TEXT NOT NULL,
        counselor_id INTEGER,
        method TEXT DEFAULT 'visit',
        contact_type TEXT DEFAULT 'client',
        content TEXT NOT NULL,
        response TEXT DEFAULT '',
        followup TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

    CREATE TABLE IF NOT EXISTS handovers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        staff_name TEXT NOT NULL,
        content TEXT NOT NULL,
        priority TEXT DEFAULT 'normal',
        is_read INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );
    CREATE TABLE IF NOT EXISTS bcp_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        bcp_type TEXT NOT NULL,
        is_created INTEGER DEFAULT 0,
        created_date TEXT DEFAULT '',
        last_review_date TEXT DEFAULT '',
        next_review_date TEXT DEFAULT '',
        staff_name TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        updated_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

    CREATE TABLE IF NOT EXISTS bcp_trainings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        training_category TEXT NOT NULL,
        training_type TEXT DEFAULT 'training',
        training_date TEXT NOT NULL,
        participants_count INTEGER DEFAULT 0,
        content TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

    CREATE TABLE IF NOT EXISTS abuse_prevention (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        record_type TEXT NOT NULL,
        record_date TEXT NOT NULL,
        attendees TEXT DEFAULT '',
        content TEXT DEFAULT '',
        next_date TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

    CREATE TABLE IF NOT EXISTS kasan_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        office_id INTEGER NOT NULL,
        kasan_name TEXT NOT NULL,
        units TEXT DEFAULT '',
        freq TEXT DEFAULT '',
        is_notified INTEGER DEFAULT 0,
        notify_date TEXT DEFAULT '',
        is_active INTEGER DEFAULT 0,
        requirement_notes TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        updated_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (office_id) REFERENCES offices(id)
    );

    """)
    conn.commit()
    conn.close()
