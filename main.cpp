// ============================================================================
// Complaint & Ticket Management System - Office POC  (C++17 + SQLite3)
//
// Build : g++ -std=c++17 -O2 main.cpp -o ticket_system.exe -lsqlite3
// Run   : .\ticket_system.exe
//
// Roles : EMPLOYEE (raises complaints), MANAGER (approves / assigns / reports),
//         AGENT    (IT support: works on assigned tickets and resolves them),
//         ADMIN    (everything + users, categories, delete, sample data)
//
// Default logins (change them before a demo!)
//    admin    / Admin@123
//    manager1 / Manager@123
//    agent1   / Agent@123   (IT Support Agent)
// Employees register themselves from the main menu.
//
// Ticket lifecycle:
//    PENDING -> APPROVED or REJECTED (manager)
//    APPROVED -> ASSIGNED (manager picks an IT support agent)
//    ASSIGNED -> IN_PROGRESS -> RESOLVED (agent, with resolution details)
//    RESOLVED -> CLOSED (manager/admin), or reopened to IN_PROGRESS
// ============================================================================

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

using namespace std;

// ============================================================================
// 1. Password hashing (salted SHA-256 - fine for a POC)
// ============================================================================
static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

string sha256(const string& msg) {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    vector<uint8_t> d(msg.begin(), msg.end());
    uint64_t bits = static_cast<uint64_t>(msg.size()) * 8;
    d.push_back(0x80);
    while (d.size() % 64 != 56) d.push_back(0);
    for (int i = 7; i >= 0; --i) d.push_back(static_cast<uint8_t>((bits >> (i * 8)) & 0xff));

    for (size_t off = 0; off < d.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(d[off + i * 4]) << 24) | (uint32_t(d[off + i * 4 + 1]) << 16) |
                   (uint32_t(d[off + i * 4 + 2]) << 8) | uint32_t(d[off + i * 4 + 3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], dd = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = dd + t1; dd = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += dd; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    ostringstream os;
    for (uint32_t v : h) os << hex << setw(8) << setfill('0') << v;
    return os.str();
}

string randomSalt() {
    random_device rd;
    ostringstream os;
    for (int i = 0; i < 4; ++i) os << hex << setw(8) << setfill('0') << rd();
    return os.str();
}

// ============================================================================
// 2. Database wrapper (prepared statements = safe from SQL injection)
// ============================================================================
struct Table {
    vector<string> cols;
    vector<vector<string>> rows;
    bool empty() const { return rows.empty(); }
};

class DB {
    sqlite3* db = nullptr;

   public:
    bool open(const string& path) {
        if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
            cerr << "DB error: " << (db ? sqlite3_errmsg(db) : "unknown error") << "\n";
            if (db) { sqlite3_close(db); db = nullptr; }
            return false;
        }
        return exec("PRAGMA foreign_keys = ON");
    }
    ~DB() { if (db) sqlite3_close(db); }

    bool script(const string& sql) {
        char* err = nullptr;
        if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
            cerr << "DB error: " << err << "\n";
            sqlite3_free(err);
            return false;
        }
        return true;
    }

    bool exec(const string& sql, const vector<string>& p = {}, bool quiet = false) {
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
            if (!quiet) cerr << "DB error: " << sqlite3_errmsg(db) << "\n";
            return false;
        }
        for (size_t i = 0; i < p.size(); ++i) {
            if (sqlite3_bind_text(st, int(i) + 1, p[i].c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
                if (!quiet) cerr << "DB error: " << sqlite3_errmsg(db) << "\n";
                sqlite3_finalize(st);
                return false;
            }
        }
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
            if (!quiet) cerr << "DB error: " << sqlite3_errmsg(db) << "\n";
            return false;
        }
        return true;
    }

    Table query(const string& sql, const vector<string>& p = {}) {
        Table t;
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
            cerr << "DB error: " << sqlite3_errmsg(db) << "\n";
            return t;
        }
        for (size_t i = 0; i < p.size(); ++i) {
            if (sqlite3_bind_text(st, int(i) + 1, p[i].c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
                cerr << "DB error: " << sqlite3_errmsg(db) << "\n";
                sqlite3_finalize(st);
                return t;
            }
        }
        int n = sqlite3_column_count(st);
        for (int i = 0; i < n; ++i) t.cols.push_back(sqlite3_column_name(st, i));
        int rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            vector<string> row;
            for (int i = 0; i < n; ++i) {
                const unsigned char* v = sqlite3_column_text(st, i);
                row.push_back(v ? reinterpret_cast<const char*>(v) : "");
            }
            t.rows.push_back(move(row));
        }
        if (rc != SQLITE_DONE) cerr << "DB error: " << sqlite3_errmsg(db) << "\n";
        sqlite3_finalize(st);
        return t;
    }

    long long lastId() { return sqlite3_last_insert_rowid(db); }
    int changes() { return sqlite3_changes(db); }
};

static DB db;

// ============================================================================
// 3. Console helpers
// ============================================================================
string trim(const string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

string upper(string s) {
    transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return char(toupper(c)); });
    return s;
}

string readLine(const string& prompt) {
    cout << prompt << flush;
    string s;
    if (!getline(cin, s)) { cout << "\nInput closed. Goodbye.\n"; exit(0); }
    return trim(s);
}

int readInt(const string& prompt) {
    while (true) {
        string s = readLine(prompt);
        try {
            size_t pos;
            int v = stoi(s, &pos);
            if (pos == s.size()) return v;
        } catch (...) {}
        cout << "  Please enter a valid number.\n";
    }
}

string readRequired(const string& prompt) {
    while (true) {
        string s = readLine(prompt);
        if (!s.empty()) return s;
        cout << "  This field cannot be empty.\n";
    }
}

static bool showPw = false;  // true = show password while typing, false = hidden

string readPassword(const string& prompt) {
    if (showPw) return readLine(prompt);
    cout << prompt << flush;
    string pw;
#ifdef _WIN32
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    bool tty = GetConsoleMode(hIn, &mode) != 0;
    if (tty) SetConsoleMode(hIn, mode & ~ENABLE_ECHO_INPUT);  // hide typing
    if (!getline(cin, pw)) { if (tty) SetConsoleMode(hIn, mode); exit(0); }
    if (tty) { SetConsoleMode(hIn, mode); cout << "\n"; }
#else
    termios oldt{};
    bool tty = tcgetattr(STDIN_FILENO, &oldt) == 0;
    if (tty) {
        termios newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    if (!getline(cin, pw)) { if (tty) tcsetattr(STDIN_FILENO, TCSANOW, &oldt); exit(0); }
    if (tty) { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); cout << "\n"; }
#endif
    return trim(pw);
}

bool confirm(const string& q) {
    string s = readLine(q + " (y/N): ");
    return s == "y" || s == "Y";
}

void printTable(const Table& t) {
    if (t.cols.empty() || t.rows.empty()) { cout << "  (no records)\n"; return; }
    const size_t MAXW = 38;
    vector<size_t> w(t.cols.size());
    for (size_t i = 0; i < t.cols.size(); ++i) w[i] = t.cols[i].size();
    for (auto& r : t.rows)
        for (size_t i = 0; i < r.size(); ++i) w[i] = min(MAXW, max(w[i], r[i].size()));
    auto cut = [&](const string& s, size_t width) {
        return s.size() > width ? s.substr(0, width - 3) + "..." : s;
    };
    auto line = [&]() {
        cout << "+";
        for (size_t x : w) cout << string(x + 2, '-') << "+";
        cout << "\n";
    };
    line();
    cout << "|";
    for (size_t i = 0; i < t.cols.size(); ++i) cout << " " << left << setw(int(w[i])) << t.cols[i] << " |";
    cout << "\n";
    line();
    for (auto& r : t.rows) {
        cout << "|";
        for (size_t i = 0; i < r.size(); ++i) cout << " " << left << setw(int(w[i])) << cut(r[i], w[i]) << " |";
        cout << "\n";
    }
    line();
    cout << "  " << t.rows.size() << " record(s)\n";
}

void header(const string& title) { cout << "\n===== " << title << " =====\n"; }

// ============================================================================
// 4. Model, constants and schema
// ============================================================================
struct User {
    int id = 0;
    string username, role, name;
};

const vector<string> PRIORITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"};
const vector<string> STATUSES = {"PENDING", "APPROVED", "REJECTED", "ASSIGNED",
                                 "IN_PROGRESS", "RESOLVED", "CLOSED"};
const vector<string> ROLES = {"EMPLOYEE", "AGENT", "MANAGER", "ADMIN"};

bool isStaff(const User& u) { return u.role == "MANAGER" || u.role == "ADMIN"; }

bool createUserRow(const string& username, const string& pw, const string& name, const string& role) {
    string salt = randomSalt();
    return db.exec("INSERT INTO users(username,full_name,role,salt,password_hash) VALUES(?,?,?,?,?)",
                   {username, name, role, salt, sha256(salt + pw)}, true);
}

// Older databases only allowed 3 roles. Rebuild the users table so AGENT is allowed (data is kept).
bool migrateUsersForAgentRole() {
    auto t = db.query("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'");
    if (t.empty() || t.rows[0][0].find("'AGENT'") != string::npos) return true;  // nothing to do
    cout << "Upgrading existing database to support the IT Support Agent role...\n";
    if (!db.script("PRAGMA foreign_keys = OFF;")) return false;
    bool ok = db.script(R"SQL(
        BEGIN;
        CREATE TABLE users_new(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('EMPLOYEE','AGENT','MANAGER','ADMIN')),
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
        INSERT INTO users_new(id,username,full_name,role,salt,password_hash,active,created_at)
            SELECT id,username,full_name,role,salt,password_hash,active,created_at FROM users;
        DROP TABLE users;
        ALTER TABLE users_new RENAME TO users;
        COMMIT;
    )SQL");
    if (!ok) db.exec("ROLLBACK", {}, true);
    db.script("PRAGMA foreign_keys = ON;");
    return ok;
}

bool initDatabase() {
    if (!migrateUsersForAgentRole()) return false;
    if (!db.script(R"SQL(
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('EMPLOYEE','AGENT','MANAGER','ADMIN')),
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS categories(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category_id INTEGER NOT NULL REFERENCES categories(id),
            priority TEXT NOT NULL CHECK(priority IN ('LOW','MEDIUM','HIGH','CRITICAL')),
            status TEXT NOT NULL DEFAULT 'PENDING',
            created_by INTEGER NOT NULL REFERENCES users(id),
            assigned_to INTEGER NOT NULL DEFAULT 0,
            approved_by INTEGER NOT NULL DEFAULT 0,
            manager_comment TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS ticket_history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
            old_status TEXT,
            new_status TEXT NOT NULL,
            changed_by INTEGER NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            changed_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
        CREATE INDEX IF NOT EXISTS idx_ticket_status ON tickets(status);
        CREATE INDEX IF NOT EXISTS idx_ticket_creator ON tickets(created_by);
        CREATE INDEX IF NOT EXISTS idx_ticket_assignee ON tickets(assigned_to);
    )SQL"))
        return false;

    if (db.query("SELECT id FROM users LIMIT 1").empty()) {
        if (!createUserRow("admin", "Admin@123", "System Administrator", "ADMIN") ||
            !createUserRow("manager1", "Manager@123", "Default Manager", "MANAGER"))
            return false;
    }
    if (db.query("SELECT id FROM categories LIMIT 1").empty()) {
        for (auto c : {"Billing", "Technical Issue", "Service Quality", "Product Defect", "Delivery", "Other"})
            if (!db.exec("INSERT INTO categories(name) VALUES(?)", {c})) return false;
    }
    if (db.query("SELECT id FROM users WHERE role='AGENT' LIMIT 1").empty())
        if (!createUserRow("agent1", "Agent@123", "IT Support Agent", "AGENT")) return false;
    return true;
}

void logHistory(int ticketId, const string& oldS, const string& newS, int by, const string& note) {
    db.exec("INSERT INTO ticket_history(ticket_id,old_status,new_status,changed_by,note) VALUES(?,?,?,?,?)",
            {to_string(ticketId), oldS, newS, to_string(by), note});
}

// ============================================================================
// 5. Registration, login, password
// ============================================================================
bool validPassword(const string& pw) {
    if (pw.size() < 6) { cout << "  Password must be at least 6 characters.\n"; return false; }
    return true;
}

bool login(User& u) {
    for (int attempt = 1; attempt <= 3; ++attempt) {
        string name = readLine("Username: ");
        string pw = readPassword("Password: ");
        auto t = db.query(
            "SELECT id,username,full_name,role,salt,password_hash,active FROM users WHERE username=?", {name});
        if (!t.empty()) {
            auto& r = t.rows[0];
            if (r[6] == "1" && sha256(r[4] + pw) == r[5]) {
                u = User{stoi(r[0]), r[1], r[3], r[2]};
                return true;
            }
        }
        cout << "  Invalid credentials or inactive account (" << attempt << "/3)\n";
    }
    return false;
}

void registerEmployee() {
    header("Employee Registration");
    string username = readRequired("Choose username: ");
    if (username.size() < 3) { cout << "  Username must be at least 3 characters.\n"; return; }
    if (!db.query("SELECT id FROM users WHERE username=?", {username}).empty()) {
        cout << "  Username already taken.\n";
        return;
    }
    string name = readRequired("Full name: ");
    string pw = readPassword("Password (min 6 chars): ");
    if (!validPassword(pw)) return;
    if (readPassword("Confirm password: ") != pw) { cout << "  Passwords do not match.\n"; return; }
    if (createUserRow(username, pw, name, "EMPLOYEE"))
        cout << "  Registration successful. You can now log in.\n";
    else
        cout << "  Registration failed. Please try a different username.\n";
}

void changePassword(const User& u) {
    string oldPw = readPassword("Current password: ");
    auto t = db.query("SELECT salt,password_hash FROM users WHERE id=?", {to_string(u.id)});
    if (t.empty() || sha256(t.rows[0][0] + oldPw) != t.rows[0][1]) { cout << "  Wrong password.\n"; return; }
    string pw = readPassword("New password: ");
    if (!validPassword(pw)) return;
    if (readPassword("Confirm new password: ") != pw) { cout << "  Passwords do not match.\n"; return; }
    string salt = randomSalt();
    if (db.exec("UPDATE users SET salt=?, password_hash=? WHERE id=?", {salt, sha256(salt + pw), to_string(u.id)}))
        cout << "  Password changed.\n";
    else
        cout << "  Could not change the password.\n";
}

// ============================================================================
// 6. Ticket helpers
// ============================================================================
const string TICKET_LIST_SQL =
    "SELECT t.id AS ID, t.title AS Title, c.name AS Category, t.priority AS Priority, t.status AS Status,"
    " u.username AS RaisedBy, IFNULL(a.username,'-') AS Handler, t.created_at AS Created "
    "FROM tickets t JOIN categories c ON c.id=t.category_id JOIN users u ON u.id=t.created_by "
    "LEFT JOIN users a ON a.id=t.assigned_to ";

// Employees see their own tickets, agents see tickets assigned to them, managers/admins see all.
string scopeClause(const User& u, vector<string>& params) {
    if (u.role == "EMPLOYEE") { params.push_back(to_string(u.id)); return " AND t.created_by=? "; }
    if (u.role == "AGENT") { params.push_back(to_string(u.id)); return " AND t.assigned_to=? "; }
    return "";
}

int chooseCategory(bool allowKeep) {
    auto cats = db.query("SELECT id AS ID, name AS Category FROM categories ORDER BY id");
    printTable(cats);
    while (true) {
        int id = readInt(allowKeep ? "Category ID (0 = keep current): " : "Category ID: ");
        if (allowKeep && id == 0) return 0;
        if (!db.query("SELECT id FROM categories WHERE id=?", {to_string(id)}).empty()) return id;
        cout << "  Invalid category.\n";
    }
}

string choosePriority(bool allowKeep) {
    cout << "Priority: 1=LOW 2=MEDIUM 3=HIGH 4=CRITICAL" << (allowKeep ? "  0=keep current" : "") << "\n";
    while (true) {
        int p = readInt("Choose: ");
        if (allowKeep && p == 0) return "";
        if (p >= 1 && p <= 4) return PRIORITIES[p - 1];
        cout << "  Invalid priority.\n";
    }
}

void listTickets(const User& u, const string& extraWhere = "", vector<string> extraParams = {},
                 const string& order = " ORDER BY t.id DESC") {
    vector<string> params;
    string sql = TICKET_LIST_SQL + "WHERE 1=1 " + scopeClause(u, params) + extraWhere + order;
    params.insert(params.end(), extraParams.begin(), extraParams.end());
    printTable(db.query(sql, params));
}

void viewTicket(const User& u, int id) {
    auto t = db.query(
        "SELECT t.id,t.title,t.description,c.name,t.priority,t.status,cu.full_name,IFNULL(au.full_name,'-'),"
        "t.manager_comment,t.created_at,t.updated_at,t.created_by,t.assigned_to "
        "FROM tickets t JOIN categories c ON c.id=t.category_id JOIN users cu ON cu.id=t.created_by "
        "LEFT JOIN users au ON au.id=t.assigned_to WHERE t.id=?",
        {to_string(id)});
    if (t.empty()) { cout << "  Ticket not found.\n"; return; }
    auto& r = t.rows[0];
    if ((u.role == "EMPLOYEE" && stoi(r[11]) != u.id) || (u.role == "AGENT" && stoi(r[12]) != u.id)) {
        cout << "  You do not have access to this ticket.\n";
        return;
    }
    header("Ticket #" + r[0]);
    cout << "Title      : " << r[1] << "\nDescription: " << r[2] << "\nCategory   : " << r[3]
         << "\nPriority   : " << r[4] << "\nStatus     : " << r[5] << "\nRaised by  : " << r[6]
         << "\nHandler    : " << r[7] << "\nMgr comment: " << (r[8].empty() ? "-" : r[8])
         << "\nCreated    : " << r[9] << "\nUpdated    : " << r[10] << "\n";
    cout << "\nStatus history:\n";
    printTable(db.query(
        "SELECT h.changed_at AS Time, IFNULL(h.old_status,'-') AS 'From', h.new_status AS 'To',"
        " u.username AS By, h.note AS Note FROM ticket_history h JOIN users u ON u.id=h.changed_by"
        " WHERE h.ticket_id=? ORDER BY h.id",
        {to_string(id)}));
}

// ============================================================================
// 7. Ticket CRUD
// ============================================================================
void createTicket(const User& u) {  // CREATE
    header("Raise a Complaint");
    string title = readRequired("Title: ");
    string desc = readRequired("Description: ");
    int cat = chooseCategory(false);
    string pri = choosePriority(false);
    if (!db.exec("INSERT INTO tickets(title,description,category_id,priority,status,created_by)"
                 " VALUES(?,?,?,?,'PENDING',?)",
                 {title, desc, to_string(cat), pri, to_string(u.id)})) {
        cout << "  Could not create the complaint. Please try again.\n";
        return;
    }
    int id = int(db.lastId());
    logHistory(id, "", "PENDING", u.id, "Ticket created");
    cout << "  Complaint registered. Ticket ID = " << id << " (awaiting manager approval)\n";
}

void editTicket(const User& u) {  // UPDATE
    int id = readInt("Ticket ID to edit: ");
    auto t = db.query("SELECT created_by,status,title,description FROM tickets WHERE id=?", {to_string(id)});
    if (t.empty()) { cout << "  Ticket not found.\n"; return; }
    auto& r = t.rows[0];
    bool staff = isStaff(u) && r[1] != "CLOSED";
    bool owner = u.role == "EMPLOYEE" && stoi(r[0]) == u.id && r[1] == "PENDING";
    if (!staff && !owner) {
        cout << "  Not allowed. Employees can edit only their own PENDING complaints;\n"
                "  managers and admins cannot edit CLOSED tickets.\n";
        return;
    }
    string title = readLine("New title (blank = keep): ");
    string desc = readLine("New description (blank = keep): ");
    int cat = chooseCategory(true);
    string pri = choosePriority(true);
    if (!db.exec("UPDATE tickets SET title=?, description=?, category_id=COALESCE(NULLIF(CAST(? AS INTEGER),0),category_id),"
                 " priority=COALESCE(NULLIF(?,''),priority), updated_at=datetime('now','localtime') WHERE id=?",
                 {title.empty() ? r[2] : title, desc.empty() ? r[3] : desc, to_string(cat), pri, to_string(id)})) {
        cout << "  Ticket update failed.\n";
        return;
    }
    logHistory(id, r[1], r[1], u.id, "Ticket details edited");
    cout << "  Ticket updated.\n";
}

void deleteTicket(const User& u) {  // DELETE
    int id = readInt("Ticket ID to delete: ");
    auto t = db.query("SELECT created_by,status FROM tickets WHERE id=?", {to_string(id)});
    if (t.empty()) { cout << "  Ticket not found.\n"; return; }
    auto& r = t.rows[0];
    bool ok = u.role == "ADMIN" || (u.role == "EMPLOYEE" && stoi(r[0]) == u.id && r[1] == "PENDING");
    if (!ok) { cout << "  Not allowed. Employees can delete only their own PENDING complaints.\n"; return; }
    if (!confirm("Delete ticket #" + to_string(id) + " permanently?")) return;
    if (db.exec("DELETE FROM tickets WHERE id=?", {to_string(id)}) && db.changes() > 0)
        cout << "  Ticket deleted.\n";
    else
        cout << "  Could not delete the ticket.\n";
}

// ============================================================================
// 8. Manager: approval/rejection, assignment, status updates
// ============================================================================
void assignTicketById(const User& u, int id) {
    auto t = db.query("SELECT status FROM tickets WHERE id=?", {to_string(id)});
    if (t.empty()) { cout << "  Ticket not found.\n"; return; }
    string st = t.rows[0][0];
    if (st != "APPROVED" && st != "ASSIGNED" && st != "IN_PROGRESS") {
        cout << "  Only APPROVED tickets can be assigned (ASSIGNED / IN_PROGRESS ones can be reassigned).\n";
        return;
    }
    auto agents = db.query(
        "SELECT u.id AS ID, u.username AS Username, u.full_name AS Name,"
        " (SELECT COUNT(*) FROM tickets x WHERE x.assigned_to=u.id AND x.status IN ('ASSIGNED','IN_PROGRESS'))"
        " AS OpenLoad FROM users u WHERE u.role='AGENT' AND u.active=1");
    if (agents.empty()) {
        cout << "  No active IT support agents. Ask an admin to add one (Manage users).\n";
        return;
    }
    printTable(agents);
    int aid = readInt("Assign to agent ID: ");
    if (db.query("SELECT id FROM users WHERE id=? AND role='AGENT' AND active=1", {to_string(aid)}).empty()) {
        cout << "  Invalid agent.\n";
        return;
    }
    if (db.exec("UPDATE tickets SET assigned_to=?, status='ASSIGNED', updated_at=datetime('now','localtime')"
                " WHERE id=? AND status IN ('APPROVED','ASSIGNED','IN_PROGRESS')",
                {to_string(aid), to_string(id)}) && db.changes() > 0) {
        logHistory(id, st, "ASSIGNED", u.id, "Assigned to IT support agent #" + to_string(aid));
        cout << "  Ticket assigned to the IT support agent.\n";
    } else {
        cout << "  Assignment failed.\n";
    }
}

void approvalQueue(const User& u) {
    header("Pending Approvals");
    listTickets(u, " AND t.status='PENDING' ", {},
                " ORDER BY CASE t.priority WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3"
                " ELSE 4 END, t.id");
    int id = readInt("Ticket ID to review (0 = back): ");
    if (id == 0) return;
    auto t = db.query("SELECT status FROM tickets WHERE id=?", {to_string(id)});
    if (t.empty() || t.rows[0][0] != "PENDING") { cout << "  Not a pending ticket.\n"; return; }
    viewTicket(u, id);
    string d = readLine("Decision: (A)pprove / (R)eject / (S)kip: ");
    if (d == "A" || d == "a") {
        string cm = readLine("Comment (optional): ");
        if (db.exec("UPDATE tickets SET status='APPROVED', approved_by=?, manager_comment=?,"
                    " updated_at=datetime('now','localtime') WHERE id=? AND status='PENDING'",
                    {to_string(u.id), cm, to_string(id)}) && db.changes() > 0) {
            logHistory(id, "PENDING", "APPROVED", u.id, cm);
            cout << "  Ticket approved.\n";
            if (confirm("Assign it to an IT support agent now?")) assignTicketById(u, id);
        } else {
            cout << "  Approval failed.\n";
        }
    } else if (d == "R" || d == "r") {
        string cm = readRequired("Reason for rejection: ");
        if (db.exec("UPDATE tickets SET status='REJECTED', approved_by=?, manager_comment=?,"
                    " updated_at=datetime('now','localtime') WHERE id=? AND status='PENDING'",
                    {to_string(u.id), cm, to_string(id)}) && db.changes() > 0) {
            logHistory(id, "PENDING", "REJECTED", u.id, cm);
            cout << "  Ticket rejected.\n";
        } else {
            cout << "  Rejection failed.\n";
        }
    } else {
        cout << "  Skipped.\n";
    }
}

void updateStatus(const User& u) {
    int id = readInt("Ticket ID: ");
    auto t = db.query("SELECT status,assigned_to FROM tickets WHERE id=?", {to_string(id)});
    bool isHandler = !t.empty() && stoi(t.rows[0][1]) == u.id;
    if (t.empty() || (u.role == "AGENT" && !isHandler)) {
        cout << "  Ticket not found" << (u.role == "AGENT" ? " or not assigned to you" : "") << ".\n";
        return;
    }
    string cur = t.rows[0][0];
    vector<string> options;
    bool canWork = (u.role == "AGENT" && isHandler) || (isStaff(u) && (isHandler || u.role == "ADMIN"));
    if (canWork) {
        if (cur == "ASSIGNED") options = {"IN_PROGRESS"};
        else if (cur == "IN_PROGRESS") options = {"RESOLVED"};
    }
    if (isStaff(u) && cur == "RESOLVED") options = {"CLOSED", "IN_PROGRESS"};
    if (options.empty()) {
        cout << "  No status change is available for you at status " << cur << ".\n"
                "  (The assigned IT support agent starts and resolves a ticket; managers close RESOLVED tickets.)\n";
        return;
    }
    for (size_t i = 0; i < options.size(); ++i) cout << "  " << i + 1 << ") " << options[i] << "\n";
    int c = readInt("Choose new status (0 = cancel): ");
    if (c < 1 || c > int(options.size())) return;
    string newSt = options[c - 1];
    string note = newSt == "RESOLVED" ? readRequired("Resolution details (what was done to fix the issue): ")
                                      : readLine("Note (optional): ");
    if (db.exec("UPDATE tickets SET status=?, updated_at=datetime('now','localtime') WHERE id=? AND status=?",
                {newSt, to_string(id), cur}) && db.changes() > 0) {
        logHistory(id, cur, newSt, u.id, note);
        cout << "  Status updated to " << newSt << (newSt == "RESOLVED" ? " - the issue is marked as resolved." : ".") << "\n";
    } else {
        cout << "  Status update failed.\n";
    }
}

// ============================================================================
// 9. Search
// ============================================================================
void searchTickets(const User& u) {
    header("Search Complaints (leave a filter blank to skip it)");
    string kw = readLine("Keyword (title/description): ");
    string st = upper(readLine("Status (PENDING/APPROVED/REJECTED/ASSIGNED/IN_PROGRESS/RESOLVED/CLOSED): "));
    string pr = upper(readLine("Priority (LOW/MEDIUM/HIGH/CRITICAL): "));
    string cat = readLine("Category ID: ");
    if (!st.empty() && find(STATUSES.begin(), STATUSES.end(), st) == STATUSES.end()) {
        cout << "  Unknown status '" << st << "'.\n";
        return;
    }
    if (!pr.empty() && find(PRIORITIES.begin(), PRIORITIES.end(), pr) == PRIORITIES.end()) {
        cout << "  Unknown priority '" << pr << "'.\n";
        return;
    }
    string where;
    vector<string> p;
    if (!kw.empty()) {
        where += " AND (t.title LIKE ? OR t.description LIKE ?) ";
        p.push_back("%" + kw + "%");
        p.push_back("%" + kw + "%");
    }
    if (!st.empty()) { where += " AND t.status=? "; p.push_back(st); }
    if (!pr.empty()) { where += " AND t.priority=? "; p.push_back(pr); }
    if (!cat.empty()) { where += " AND t.category_id=? "; p.push_back(cat); }
    listTickets(u, where, p);
}

// ============================================================================
// 10. Dashboard and reports
// ============================================================================
Table withBar(Table t) {  // adds a text bar chart column based on column 1 (the count)
    t.cols.push_back("Chart");
    int mx = 0;
    for (auto& r : t.rows) mx = max(mx, atoi(r[1].c_str()));
    for (auto& r : t.rows) {
        int n = atoi(r[1].c_str());
        string bar(mx ? size_t(n * 25 / mx) : 0, '#');
        if (n > 0 && bar.empty()) bar = "#";
        r.push_back(bar);
    }
    return t;
}

void dashboard(const User& u) {
    header((u.role == "EMPLOYEE" || u.role == "AGENT") ? "My Dashboard" : "Dashboard");
    vector<string> p;
    string sc = scopeClause(u, p);
    auto group = [&](const string& title, const string& col, const string& join = "") {
        cout << "\n" << title << "\n";
        printTable(withBar(db.query("SELECT " + col + " AS Name, COUNT(*) AS Count FROM tickets t " + join +
                                    " WHERE 1=1 " + sc + " GROUP BY " + col + " ORDER BY Count DESC", p)));
    };
    auto total = db.query("SELECT COUNT(*) FROM tickets t WHERE 1=1 " + sc, p);
    cout << "Total complaints: " << (total.empty() ? "0" : total.rows[0][0]) << "\n";
    group("By status", "t.status");
    group("By priority", "t.priority");
    group("By category", "c.name", "JOIN categories c ON c.id=t.category_id");
    if (isStaff(u)) {
        auto pend = db.query("SELECT COUNT(*) FROM tickets WHERE status='PENDING'");
        auto unas = db.query("SELECT COUNT(*) FROM tickets WHERE status='APPROVED'");
        auto crit = db.query("SELECT COUNT(*) FROM tickets WHERE priority='CRITICAL' AND status NOT IN"
                             " ('RESOLVED','CLOSED','REJECTED')");
        cout << "\nAwaiting approval: " << pend.rows[0][0] << " | Approved but unassigned: " << unas.rows[0][0]
             << " | Open CRITICAL: " << crit.rows[0][0] << "\n";
    }
}

string csvEscape(string s) {
    if (!s.empty() && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@')) s = "'" + s;  // spreadsheet safety
    string o = "\"";
    for (char c : s) { if (c == '"') o += "\"\""; else o += c; }
    return o + "\"";
}

void exportCsv() {
    auto t = db.query(
        "SELECT t.id,t.title,t.description,c.name,t.priority,t.status,u.username,IFNULL(a.username,''),"
        "t.manager_comment,t.created_at,t.updated_at FROM tickets t JOIN categories c ON c.id=t.category_id"
        " JOIN users u ON u.id=t.created_by LEFT JOIN users a ON a.id=t.assigned_to ORDER BY t.id");
    const string file = "complaints_report.csv";
    ofstream f(file, ios::binary);
    if (!f) {
        cout << "  Could not write " << file << ". Close it if it is open in Excel and try again.\n";
        return;
    }
    f << "\xEF\xBB\xBF" << "ID,Title,Description,Category,Priority,Status,Raised By,Handler,Manager Comment,Created,Updated\r\n";
    for (auto& r : t.rows) {
        for (size_t i = 0; i < r.size(); ++i) f << (i ? "," : "") << csvEscape(r[i]);
        f << "\r\n";
    }
    f.close();
    if (!f) { cout << "  Writing the report failed.\n"; return; }
    cout << "  Exported " << t.rows.size() << " complaint(s) to " << file << " (in the program folder).\n";
}

void reportsMenu() {
    while (true) {
        header("Reports");
        cout << "1) Export all complaints to CSV (opens in Excel)\n2) Category report\n"
                "3) Agent workload report\n4) Priority vs status report\n0) Back\n";
        int c = readInt("Choose: ");
        if (c == 0) return;
        if (c == 1) exportCsv();
        else if (c == 2)
            printTable(db.query(
                "SELECT c.name AS Category, COUNT(t.id) AS Total,"
                " COALESCE(SUM(t.status='PENDING'),0) AS Pending,"
                " COALESCE(SUM(t.status IN ('APPROVED','ASSIGNED','IN_PROGRESS')),0) AS Active,"
                " COALESCE(SUM(t.status IN ('RESOLVED','CLOSED')),0) AS Done,"
                " COALESCE(SUM(t.status='REJECTED'),0) AS Rejected "
                "FROM categories c LEFT JOIN tickets t ON t.category_id=c.id GROUP BY c.id ORDER BY Total DESC"));
        else if (c == 3)
            printTable(db.query(
                "SELECT u.username AS Agent, u.role AS Role,"
                " COALESCE(SUM(t.status IN ('ASSIGNED','IN_PROGRESS')),0) AS Active,"
                " COALESCE(SUM(t.status IN ('RESOLVED','CLOSED')),0) AS Done, COUNT(t.id) AS Total "
                "FROM users u LEFT JOIN tickets t ON t.assigned_to=u.id WHERE u.role='AGENT' OR t.id IS NOT NULL"
                " GROUP BY u.id ORDER BY Active DESC"));
        else if (c == 4)
            printTable(db.query(
                "SELECT t.priority AS Priority, COUNT(*) AS Total,"
                " SUM(t.status='PENDING') AS Pending,"
                " SUM(t.status IN ('APPROVED','ASSIGNED','IN_PROGRESS')) AS Active,"
                " SUM(t.status IN ('RESOLVED','CLOSED')) AS Done, SUM(t.status='REJECTED') AS Rejected "
                "FROM tickets t GROUP BY t.priority ORDER BY CASE t.priority WHEN 'CRITICAL' THEN 1"
                " WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END"));
        else cout << "  Invalid option.\n";
    }
}

// ============================================================================
// 11. Admin: users, categories, sample data
// ============================================================================
string chooseRole() {
    cout << "Role: 1=EMPLOYEE 2=IT SUPPORT AGENT 3=MANAGER 4=ADMIN\n";
    int r = readInt("Choose: ");
    if (r < 1 || r > 4) { cout << "  Invalid role.\n"; return ""; }
    return ROLES[r - 1];
}

void manageUsers(const User& me) {
    while (true) {
        header("User Management");
        cout << "1) List users\n2) Add user\n3) Change role\n4) Activate / Deactivate\n"
                "5) Reset password\n6) Delete user\n0) Back\n";
        int c = readInt("Choose: ");
        if (c == 0) return;
        if (c == 1) {
            printTable(db.query("SELECT id AS ID, username AS Username, full_name AS Name, role AS Role,"
                                " CASE active WHEN 1 THEN 'Yes' ELSE 'No' END AS Active FROM users ORDER BY id"));
        } else if (c == 2) {
            string un = readRequired("Username: ");
            if (un.size() < 3) { cout << "  Username must be at least 3 characters.\n"; continue; }
            if (!db.query("SELECT id FROM users WHERE username=?", {un}).empty()) { cout << "  Already exists.\n"; continue; }
            string nm = readRequired("Full name: ");
            string role = chooseRole();
            if (role.empty()) continue;
            string pw = readPassword("Password: ");
            if (!validPassword(pw)) continue;
            cout << (createUserRow(un, pw, nm, role) ? "  User created.\n" : "  Could not create the user.\n");
        } else if (c == 3) {
            int id = readInt("User ID: ");
            if (id == me.id) { cout << "  You cannot change your own role.\n"; continue; }
            string role = chooseRole();
            if (role.empty()) continue;
            db.exec("UPDATE users SET role=? WHERE id=?", {role, to_string(id)});
            cout << (db.changes() ? "  Role updated.\n" : "  User not found.\n");
        } else if (c == 4) {
            int id = readInt("User ID: ");
            if (id == me.id) { cout << "  You cannot deactivate your own account.\n"; continue; }
            auto busy = db.query("SELECT COUNT(*) FROM tickets WHERE assigned_to=? AND status IN ('ASSIGNED','IN_PROGRESS')",
                                 {to_string(id)});
            db.exec("UPDATE users SET active = 1 - active WHERE id=?", {to_string(id)});
            bool ok = db.changes() > 0;
            cout << (ok ? "  Status toggled (see List users).\n" : "  User not found.\n");
            if (ok && !busy.empty() && busy.rows[0][0] != "0")
                cout << "  Note: this user still has " << busy.rows[0][0]
                     << " active ticket(s). Use 'Assign ticket' to reassign them.\n";
        } else if (c == 5) {
            int id = readInt("User ID: ");
            if (db.query("SELECT id FROM users WHERE id=?", {to_string(id)}).empty()) { cout << "  User not found.\n"; continue; }
            string pw = readPassword("New password: ");
            if (!validPassword(pw)) continue;
            string salt = randomSalt();
            cout << (db.exec("UPDATE users SET salt=?, password_hash=? WHERE id=?", {salt, sha256(salt + pw), to_string(id)})
                         ? "  Password reset.\n" : "  Could not reset the password.\n");
        } else if (c == 6) {
            int id = readInt("User ID: ");
            if (id == me.id) { cout << "  You cannot delete your own account.\n"; continue; }
            if (db.query("SELECT id FROM users WHERE id=?", {to_string(id)}).empty()) { cout << "  User not found.\n"; continue; }
            auto used = db.query(
                "SELECT (SELECT COUNT(*) FROM tickets WHERE created_by=?1 OR assigned_to=?1 OR approved_by=?1)"
                " + (SELECT COUNT(*) FROM ticket_history WHERE changed_by=?1)", {to_string(id)});
            if (!used.empty() && used.rows[0][0] != "0") {
                cout << "  Cannot delete: this user appears in tickets/history. Deactivate the account instead.\n";
                continue;
            }
            if (!confirm("Delete user permanently?")) continue;
            cout << (db.exec("DELETE FROM users WHERE id=?", {to_string(id)}) && db.changes() ? "  User deleted.\n"
                                                                                               : "  Could not delete the user.\n");
        } else cout << "  Invalid option.\n";
    }
}

void manageCategories() {
    while (true) {
        header("Category Management");
        cout << "1) List\n2) Add\n3) Rename\n4) Delete\n0) Back\n";
        int c = readInt("Choose: ");
        if (c == 0) return;
        if (c == 1) printTable(db.query("SELECT id AS ID, name AS Category FROM categories ORDER BY id"));
        else if (c == 2) {
            string n = readRequired("Category name: ");
            cout << (db.exec("INSERT INTO categories(name) VALUES(?)", {n}, true) ? "  Added.\n" : "  Already exists.\n");
        } else if (c == 3) {
            int id = readInt("Category ID: ");
            string n = readRequired("New name: ");
            bool ok = db.exec("UPDATE categories SET name=? WHERE id=?", {n, to_string(id)}, true);
            cout << (ok && db.changes() ? "  Renamed.\n" : "  Not found, or that name is already used.\n");
        } else if (c == 4) {
            int id = readInt("Category ID: ");
            if (db.query("SELECT id FROM categories WHERE id=?", {to_string(id)}).empty()) { cout << "  Not found.\n"; continue; }
            if (db.exec("DELETE FROM categories WHERE id=?", {to_string(id)}, true) && db.changes())
                cout << "  Deleted.\n";
            else
                cout << "  Cannot delete: this category is used by tickets.\n";
        } else cout << "  Invalid option.\n";
    }
}

// Fills the system with demo employees and complaints in every status.
void loadSampleData(const User& admin) {
    if (!db.query("SELECT id FROM users WHERE username='emp1'").empty()) {
        cout << "  Sample data was already loaded.\n";
        return;
    }
    auto cats = db.query("SELECT id FROM categories ORDER BY id");
    if (cats.empty()) { cout << "  Add at least one category first.\n"; return; }
    auto ag = db.query("SELECT id FROM users WHERE role='AGENT' AND active=1 ORDER BY id LIMIT 1");
    if (ag.empty()) { cout << "  Add an IT Support Agent first (Manage users).\n"; return; }
    int agentId = stoi(ag.rows[0][0]);
    for (auto [un, nm] : vector<pair<string, string>>{{"emp1", "Priya Sharma"}, {"emp2", "Arun Kumar"}, {"emp3", "Meena Iyer"}})
        createUserRow(un, "Employee@123", nm, "EMPLOYEE");

    auto mgr = db.query("SELECT id FROM users WHERE username='manager1'");
    int mgrId = mgr.empty() ? admin.id : stoi(mgr.rows[0][0]);

    struct S { const char *title, *desc; int cat; const char *pri, *status, *emp, *comment; };
    const S samples[] = {
        {"Invoice shows wrong amount", "October invoice is higher than the agreed rate.", 0, "HIGH", "PENDING", "emp1", ""},
        {"Laptop keeps freezing", "Laptop freezes several times a day during meetings.", 1, "CRITICAL", "APPROVED", "emp2", "Urgent - affects client work"},
        {"Rude behaviour at help desk", "Help desk staff was dismissive about my request.", 2, "MEDIUM", "ASSIGNED", "emp3", "Please look into this"},
        {"Projector not working in Room 4", "Projector shows no signal on all cables.", 1, "HIGH", "IN_PROGRESS", "emp1", "Checking cables and input settings"},
        {"AC not cooling on 2nd floor", "Second floor AC has not cooled for a week.", 5, "LOW", "RESOLVED", "emp2", "Gas refilled and filters cleaned"},
        {"Reimbursement not credited", "Travel reimbursement is pending for 2 months.", 0, "MEDIUM", "CLOSED", "emp3", "Credited on the 5th, verified with employee"},
        {"Duplicate complaint test", "Same issue as an earlier ticket.", 5, "LOW", "REJECTED", "emp1", "Duplicate of an earlier ticket"},
        {"Courier damaged my parcel", "Office parcel arrived with a broken box.", 4, "HIGH", "PENDING", "emp2", ""},
    };
    static const vector<string> chain = {"PENDING", "APPROVED", "ASSIGNED", "IN_PROGRESS", "RESOLVED", "CLOSED"};
    int made = 0;
    for (const S& s : samples) {
        auto e = db.query("SELECT id FROM users WHERE username=?", {s.emp});
        if (e.empty()) continue;
        string status = s.status;
        auto pos = find(chain.begin(), chain.end(), status);
        size_t k = pos == chain.end() ? 0 : size_t(pos - chain.begin());  // how far along the lifecycle
        bool approved = status != "PENDING";
        bool handled = k >= 2;
        string catId = cats.rows[size_t(s.cat) % cats.rows.size()][0];
        bool mgrNote = status == "REJECTED" || (k >= 1 && k <= 2);
        if (!db.exec("INSERT INTO tickets(title,description,category_id,priority,status,created_by,assigned_to,"
                     "approved_by,manager_comment) VALUES(?,?,?,?,?,?,?,?,?)",
                     {s.title, s.desc, catId, s.pri, status, e.rows[0][0], handled ? to_string(agentId) : "0",
                      approved ? to_string(mgrId) : "0", mgrNote ? s.comment : ""}))
            continue;
        int tid = int(db.lastId());
        logHistory(tid, "", "PENDING", stoi(e.rows[0][0]), "Ticket created");
        if (status == "REJECTED") {
            logHistory(tid, "PENDING", "REJECTED", mgrId, s.comment);
        } else {
            for (size_t j = 1; j <= k; ++j) {
                const string& to = chain[j];
                int by = (to == "IN_PROGRESS" || to == "RESOLVED") ? agentId : mgrId;
                string note = to == "APPROVED" ? "Approved" : to == "ASSIGNED" ? "Assigned to IT support agent"
                            : to == "IN_PROGRESS" ? "Started work" : to == "RESOLVED" ? "Issue fixed" : "Closed by manager";
                if (j == k && s.comment[0] != '\0') note = s.comment;
                logHistory(tid, chain[j - 1], to, by, note);
            }
        }
        ++made;
    }
    cout << "  Loaded 3 demo employees (emp1, emp2, emp3 - password Employee@123) and " << made
         << " sample complaints.\n";
}

// ============================================================================
// 12. Role-based menus
// ============================================================================
void employeeMenu(const User& u) {
    while (true) {
        header("EMPLOYEE MENU - " + u.name);
        cout << "1) Raise a complaint\n2) My complaints\n3) View complaint details / track status\n"
                "4) Edit my pending complaint\n5) Delete my pending complaint\n6) Search my complaints\n"
                "7) My dashboard\n8) Change password\n0) Logout\n";
        switch (readInt("Choose: ")) {
            case 1: createTicket(u); break;
            case 2: listTickets(u); break;
            case 3: viewTicket(u, readInt("Ticket ID: ")); break;
            case 4: editTicket(u); break;
            case 5: deleteTicket(u); break;
            case 6: searchTickets(u); break;
            case 7: dashboard(u); break;
            case 8: changePassword(u); break;
            case 0: return;
            default: cout << "  Invalid option.\n";
        }
    }
}

void agentMenu(const User& u) {
    while (true) {
        header("IT SUPPORT AGENT MENU - " + u.name);
        cout << "1) My assigned tickets\n2) View ticket details\n3) Update ticket status (start / resolve)\n"
                "4) Search my tickets\n5) My dashboard\n6) Change password\n0) Logout\n";
        switch (readInt("Choose: ")) {
            case 1: header("My Assigned Tickets"); listTickets(u); break;
            case 2: viewTicket(u, readInt("Ticket ID: ")); break;
            case 3: updateStatus(u); break;
            case 4: searchTickets(u); break;
            case 5: dashboard(u); break;
            case 6: changePassword(u); break;
            case 0: return;
            default: cout << "  Invalid option.\n";
        }
    }
}

void managerMenu(const User& u) {  // used for MANAGER and ADMIN
    bool admin = u.role == "ADMIN";
    while (true) {
        header(string(admin ? "ADMIN" : "MANAGER") + " MENU - " + u.name);
        cout << "1) All complaints\n2) Approval queue (approve / reject)\n3) Assign ticket to an IT support agent\n"
                "4) Tickets assigned to me\n5) View ticket details\n6) Edit ticket (category / priority / details)\n"
                "7) Update ticket status\n8) Search complaints\n9) Dashboard\n10) Reports and CSV export\n"
                "11) Change password\n";
        if (admin) cout << "12) Delete ticket\n13) Manage users\n14) Manage categories\n15) Load sample data (demo)\n";
        cout << "0) Logout\n";
        int c = readInt("Choose: ");
        if (c == 0) return;
        switch (c) {
            case 1: header("All Complaints"); listTickets(u); break;
            case 2: approvalQueue(u); break;
            case 3: assignTicketById(u, readInt("Ticket ID: ")); break;
            case 4: header("Assigned To Me");
                    listTickets(u, " AND t.assigned_to=? ", {to_string(u.id)}); break;
            case 5: viewTicket(u, readInt("Ticket ID: ")); break;
            case 6: editTicket(u); break;
            case 7: updateStatus(u); break;
            case 8: searchTickets(u); break;
            case 9: dashboard(u); break;
            case 10: reportsMenu(); break;
            case 11: changePassword(u); break;
            case 12: if (admin) deleteTicket(u); else cout << "  Invalid option.\n"; break;
            case 13: if (admin) manageUsers(u); else cout << "  Invalid option.\n"; break;
            case 14: if (admin) manageCategories(); else cout << "  Invalid option.\n"; break;
            case 15: if (admin) loadSampleData(u); else cout << "  Invalid option.\n"; break;
            default: cout << "  Invalid option.\n";
        }
    }
}

// ============================================================================
int main() {
    cout << "========================================\n"
            "   COMPLAINT AND TICKET MANAGEMENT\n"
            "========================================\n";

    if (!db.open("complaints_poc.db")) { cout << "Unable to open database.\n"; return 1; }
    if (!initDatabase()) { cout << "Database initialization failed.\n"; return 1; }
    cout << "\nDatabase connected successfully!\n";

    while (true) {
        header("MAIN MENU");
        cout << "1) Employee registration\n2) Login\n0) Exit\n";
        int choice = readInt("Choose: ");
        if (choice == 0) break;
        if (choice == 1) {
            showPw = confirm("Show password while typing?");
            registerEmployee();
        } else if (choice == 2) {
            showPw = confirm("Show password while typing?");
            User u;
            if (!login(u)) { cout << "\nLogin failed. Please try again.\n"; continue; }
            cout << "\nLogin successful! Welcome, " << u.name << " [" << u.role << "]\n";
            if (u.role == "EMPLOYEE") employeeMenu(u);
            else if (u.role == "AGENT") agentMenu(u);
            else managerMenu(u);  // MANAGER and ADMIN
        } else {
            cout << "  Invalid option.\n";
        }
    }
    cout << "\nThank you for using the system!\n";
    return 0;
}