# The Agency — Private Cybersecurity Concierge

> *"Discreet perimeter surveillance and tranquility for the world's most private estates."*

A cybersecurity monitoring dashboard designed like an ultra-luxury nature-retreat editorial journal rather than an alarmist, neon-green hacker terminal. Built with warm cream surfaces (`#F4F1EA`), deep forest-green panels (`#1C2A20`), soft sage and olive accents (`#6B705C`), terracotta indicators (`#B5654A`), serif typography, and inline botanical line art.

---

## The Story

Traditional cybersecurity operations centers drown operators in sirens, blinking red lights, and cognitive fatigue. **The Agency** operates under an opposing philosophy: **quiet sanctuary**. 

When an adversary unleashes a volumetric SYN flood or anomalous ingress probe against estate infrastructure:
1. **The Telemetry Feed** detects the anomaly in real time with smooth scrolling telemetry.
2. **Module 4 (Formal Logic)** derives base facts from packet windows and executes forward-chaining Horn clause deduction to classify the attack with a mathematical proof trace.
3. **Module 5 (Bayesian Probability)** converts prior odds through successive likelihood ratios across independent packet features to calculate the exact posterior probability of malice.
4. **Module 6 (STRIPS Planner)** searches the state space using forward breadth-first search (BFS) to synthesize an optimal 3-step defensive containment sequence.
5. **Stage 6 Autonomous Defense & GenAI** applies the blocklist to isolate the hostile IP, returns network traffic to calm, and commissions an editorial incident report formatted as an estate folio dispatch.

---

## System Architecture

```mermaid
flowchart TD
    subgraph Browser ["Client Interface (Vanilla ES6 + Chart.js)"]
        UI["Editorial Dashboard & Frosted Cards"]
        Chart["Real-time Rolling Telemetry Chart"]
        WSClient["Resilient WebSocket Client (Auto-Reconnect)"]
    end

    subgraph Backend ["FastAPI Application (ASGI)"]
        Auth["SessionMiddleware (Signed Cookies & Auth Guard)"]
        RateLimit["Rate Limiter (In-Memory Sliding Window)"]
        SimLoop["Background Simulator Worker (1s Tick)"]
        WSManager["WebSocket Connection Manager"]
        Pipeline["Autonomous Response Coordinator"]
    end

    subgraph AI_Engines ["Core Cognitive AI Modules"]
        M4["Module 4: Formal Logic\n(Forward Chaining Horn Clauses)"]
        M5["Module 5: Bayesian Probability\n(Odds Formulation & Likelihood Tables)"]
        M6["Module 6: STRIPS Planner\n(Breadth-First State Search)"]
        GenAI["GenAI Incident Reporter\n(Gemini 2.5 Flash + Fallback Template)"]
    end

    subgraph Storage ["Persistence (SQLite3)"]
        DB[("agency.db\nPRAGMA integrity_check")]
        T_Users["users (bcrypt hashes)"]
        T_Incidents["incidents (status, prob, plan_json)"]
        T_Reports["reports (editorial body, model)"]
    end

    Browser <-->|HTTP / JSON / Form Data| Auth
    WSClient <-->|WebSocket Stream (/ws)| WSManager
    SimLoop -->|1s Telemetry Broadcast| WSManager
    SimLoop -->|Trigger when Attack Active| M4
    M4 -->|Deduction & Proof Trace| Pipeline
    Pipeline -->|Evaluate Evidence| M5
    M5 -->|Posterior Probability| Pipeline
    Pipeline -->|Synthesize Containment Plan| M6
    M6 -->|3-Step Action Sequence| Pipeline
    Pipeline -->|Generate Estate Dispatch| GenAI
    Pipeline -->|Apply Blocklist & Unblock| SimLoop
    Pipeline -->|Persist Audit Record| DB
    DB --- T_Users
    DB --- T_Incidents
    DB --- T_Reports
```

---

## Deep Dive: Core AI Modules

### 1. Module 4: Formal Logic (`modules/logic.py`)
- **Pure Functions & No I/O:** Operates strictly on in-memory rolling packet windows.
- **Base Fact Derivation:**
  - `high_syn_rate(IP)`: $> 15$ SYN packets from IP in the last 1 second.
  - `single_target_port(IP, Port)`: $\ge 90\%$ of IP packets target a single port.
  - `many_ports(IP)`: $> 8$ distinct destination ports within 5 seconds.
  - `many_ssh_attempts(IP)`: $> 10$ packets to port 22 within 5 seconds.
- **Horn Clause Knowledge Base:**
  - `high_syn_rate(X) ∧ single_target_port(X, P) → ddos(X)`
  - `many_ports(X) → port_scan(X)`
  - `many_ssh_attempts(X) → brute_force(X)`
  - `ddos(X) → malicious(X)`
  - `port_scan(X) → malicious(X)`
  - `brute_force(X) → malicious(X)`
- **Forward-Chaining Engine:** Repeatedly applies inference rules until a fixed point is reached. Returns the attack classification and a human-readable proof trace explaining every deduction step.

### 2. Module 5: Bayesian Probability (`modules/bayes.py`)
- **Formulation:** Evaluates threat probability using the odds form of Bayes' Rule:
  $$\text{Odds}_{\text{posterior}} = \text{Odds}_{\text{prior}} \times \prod_{i} \text{Likelihood Ratio}_i$$
  $$\text{where } \text{Likelihood Ratio} = \frac{P(\text{Feature}_i \mid \text{Malicious})}{P(\text{Feature}_i \mid \text{Normal})}$$
- **Configurable Prior:** $P(\text{Malicious}) = 0.05$ (prior odds $\approx 0.0526$).
- **Independent Feature Likelihood Tables:**
  - **Packet Size:** Unusual ($> 1300$ or $< 60$ B): $P(\cdot \mid M)=0.60, P(\cdot \mid N)=0.02$ ($\text{LR} = 30.0$).
  - **SYN Flag:** Present: $P(\cdot \mid M)=0.60, P(\cdot \mid N)=0.10$ ($\text{LR} = 6.0$).
  - **Source Rate:** High ($> 15$ pkt/s): $P(\cdot \mid M)=0.70, P(\cdot \mid N)=0.35$ ($\text{LR} = 2.0$).
- **Conversion:** Posterior probability $P = \frac{\text{Odds}}{1 + \text{Odds}}$, animating the radial SVG gauge from 5% to ~95%.

### 3. Module 6: STRIPS Defense Planner (`modules/planner.py`)
- **State Representation:** Immutable `frozenset` of atomic proposition strings.
  - Initial State: `{"attack_detected"}`
  - Goal State: `{"threat_blocked", "block_verified"}`
- **Action Schema:** Stored as structured data with explicit preconditions, add effects, delete effects, and templated descriptions:
  - `identify_source_ip`: Pre: `{"attack_detected"}` $\rightarrow$ Add: `{"ip_identified"}`
  - `add_firewall_rule`: Pre: `{"ip_identified"}` $\rightarrow$ Add: `{"threat_blocked"}`
  - `verify_block`: Pre: `{"threat_blocked"}` $\rightarrow$ Add: `{"block_verified"}`
  - *Distractor actions* (`rate_limit_port`, `notify_admin`) are safely pruned during minimal path search.
- **Search Algorithm:** Breadth-first forward search over the state space. Guarantees finding the optimal minimal sequence of actions.

### 4. GenAI Luxury Concierge Reporting (`genai.py`)
- **Prompt Engineering:** Directs Google Gemini (`gemini-2.5-flash`) to write an understated, 120–180 word incident dispatch in the calm tone of a private estate concierge.
- **Privacy Guarantees:** 
  - `GEMINI_API_KEY` is loaded on the backend only; never logged, never printed, and never exposed to the client.
- **Resilient Fallback:** 
  - If the API key is missing, network fails, or model rejects the request, a 15-second `ThreadPoolExecutor` timeout activates the procedural luxury fallback report. The UI seamlessly tags the source as `Gemini` or `Template`.

---

## Quickstart

### 1. Clone & Environment Setup
```bash
git clone https://github.com/saarasuman/jj.git
cd jj

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Environment Configuration
```bash
cp .env.example .env
```
*(Optional)* Add your Gemini API key in `.env`:
```ini
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
SESSION_SECRET=retreat-sanctuary-secret-key-32b
```

### 3. Launch the Server
```bash
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```
Navigate to: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## Demo Credentials

The database automatically seeds an authorized concierge agent on first startup:
- **Agent Identifier:** `agent001`
- **Passphrase:** `olive-and-cream`

---

## Test Suite & Verification

The project includes a comprehensive suite of unit, property, and end-to-end integration tests:
```bash
venv/bin/pytest -v
```

### Test Coverage Highlights:
- **`test_app.py`:** Session auth, rate limiting (5 attempts / 5 mins), WebSocket 1008 rejection, replay cache, security headers, custom 404/500 error pages, and full end-to-end attack story lifecycle.
- **`test_db.py`:** Table creation, password hashing, parameterized queries, incident/report linkage, and automatic corruption recovery (`PRAGMA integrity_check`).
- **`test_logic.py`:** Forward chaining engine, Horn clause deduction, proof trace generation, and termination bounds.
- **`test_bayes.py`:** Mathematical precision of odds updating, feature monotonicity, and worked-example verification.
- **`test_planner.py`:** BFS optimality, precondition reachability, distractor action pruning, and unsolvable goal handling.
- **`test_genai.py`:** SDK client generation, mock failure handling, and procedural fallback compliance.
- **`test_simulator.py`:** Gaussian packet distributions, rolling window pruning, and blocklist dropping.

---

## Database Schema Reference

SQLite database schema (`agency.db`):

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    probability REAL NOT NULL,
    status TEXT NOT NULL,        -- 'detected', 'ended', 'blocked'
    plan_json TEXT               -- Serialized STRIPS plan object
);

CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id),
    ts TEXT NOT NULL,
    body TEXT NOT NULL,
    generated_by TEXT NOT NULL   -- 'gemini' or 'fallback'
);
```

---

## Troubleshooting

- **Port 8000 already bound:**
  Run on an alternate port: `uvicorn app:app --port 8080 --reload`
- **Gemini API Key rejected or missing:**
  The application automatically operates in fallback mode with zero downtime, producing luxury templated reports.
- **Session secret warning on startup:**
  If `SESSION_SECRET` is unset or left as `"change-me"`, an ephemeral 256-bit secret is generated automatically so the server runs safely without interruption.
- **Database corrupted or unreadable:**
  `init_db()` runs `PRAGMA integrity_check;` on startup. If corruption is detected, the damaged file is safely reset and `agent001` is re-seeded.
