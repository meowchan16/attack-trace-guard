# The Agency — 2-Minute Demo Presentation Script

> *"Welcome to The Agency. We believe true security in high-stakes environments should feel like a sanctuary, not an emergency room."*

---

## 2-Minute Presentation Walkthrough

### 0:00 – 0:25 · Introduction & Baseline Serenity
- **What to Click:** Open `http://127.0.0.1:8000/login`, enter `agent001` / `olive-and-cream`, and log in to the dashboard.
- **What to Say:**
  > "Most cybersecurity interfaces are dark, noisy, and alarmist. The Agency is an autonomous defense concierge built with a calm, editorial aesthetic for luxury estates. Notice the live rolling telemetry chart: traffic is quietly humming at 4 to 6 packets per second, and our status confirms: *'All quiet on the network.'*"
- **What the Audience Sees:**
  - Warm cream and deep forest green layout.
  - Live Chart.js telemetry line in calm olive (`#6B705C`).
  - Active status dot glowing green.

---

### 0:25 – 0:50 · Select Vector & Perimeter Intrusion (Modules 4 & 7)
- **What to Click:** Choose an attack vector from the dropdown next to Launch Attack (e.g., **Botnet**, **Port scan**, or **DDoS**), then click **"Launch Attack"**.
- **What to Say:**
  > "Notice our vector selector: we can simulate a volumetric DDoS, a distributed 5-node botnet, a port scan, or an SSH brute force. Watch as I launch a Botnet attack. Telemetry instantly spikes and shifts to terracotta. The UI automatically smooth-scrolls to our new 'Case File' folio, flashing its border once. Concurrently, Module 7—our AI route tracer—benchmarks uninformed BFS against heuristic A* search: A* explores only 4 nodes compared to 9 for BFS, locating the adversary's attack path through the estate 56% faster."
- **What the Audience Sees:**
  - Real-time line chart spikes to ~45 pps and shifts to terracotta (`#B5654A`).
  - Hero status changes to *"A disturbance at the gate..."*.
  - Smooth-scroll directly to **The Case File** with a subtle terracotta flash.
  - **Network Map Topology:** terracotta pulse animates along the traced route (`Gateway Router -> External Firewall -> Core Switch -> Web Server`).
  - Search metric chip displays: *"A* searched 4 nodes vs 9 for BFS (56% faster)"*.

---

### 0:50 – 1:15 · The Case File: WHEN, WHERE & HOW
- **What to Say:**
  > "Look at The Case File: it delivers complete situational awareness without alarmism. Under WHEN, we see exact intrusion timestamps. Under WHERE, our simulated geolocation renders the attacker's origin on our interactive SVG World Map, plotting a curved geodesic arc directly to our London headquarters. Under HOW, plain-English forensics specify the exact vector and Horn-clause rule that fired. Below, the Chronicle vertical timeline ticks through the sequence from attack inception to resolution."
- **What the Audience Sees:**
  - Case File header showing "Case File No. 00X" with status chip.
  - Interactive SVG World Map showing pulsating attacker coordinates and golden arc to London.
  - Tabbed interface for multi-attacker botnets allowing inspection of each source IP.
  - Vertical Chronicle timeline nodes activating in real time.
  - In Three Columns: Module 4 proof trace, Module 5 radial Bayesian odds gauge (animating from 5% to ~95%), and Module 6 STRIPS 3-step action plan.

---

### 1:15 – 1:40 · Autonomous Defense & Editorial Dispatch
- **What to Say:**
  > "Watch the telemetry chart: our automated STRIPS planner executes the firewall block at the perimeter. The closed-gate icon locks in the Network Map, the attack path turns serene olive, and traffic drops immediately back to quiet baseline. Simultaneously, GenAI crafts an understated incident dispatch enriched with the attacker's geographic origin, formatted in classic editorial typography."
- **What the Audience Sees:**
  - Telemetry chart drops back to ~5 pps; color shifts back to serene olive.
  - Network Map node transitions from hostile terracotta to blocked olive with a closed-gate badge.
  - Hero status updates to: *"Threat blocked. All quiet on the network."*
  - Magazine Feature populates with a 3-paragraph editorial dispatch tagged `Gemini` (or `Template`).

---

### 1:40 – 2:00 · Session Watchlist, Archives & Reset Ritual
- **What to Click:** Scroll down to the **Watchlist** and **Back Issues**, expand the newest incident accordion, then scroll up and click **"Reset demo"**.
- **What to Say:**
  > "Here in the Session Watchlist, every hostile IP detected during our shift is indexed with country flags and coordinates. Clicking any entry highlights them on the world map. Below, 'Back Issues' permanently archives the complete case file—including origin cities and AI search routes. When ready for the next demonstration, clicking 'Reset demo' safely unblocks the firewall while keeping historical memory intact."
- **What the Audience Sees:**
  - Watchlist table showing attacker IPs, country flags, cities, and status badges.
  - Expanded Back Issues accordion displaying origin geolocation, response duration, and plan steps.
  - Clicking "Reset demo" returns the UI to initial tranquility, ready for another demonstration cycle.

---

## Contingency Guidance: What If Something Goes Wrong?

1. **Gemini API Call Times Out or Key is Rejected:**
   - *Don't panic.* The backend features a robust 15-second `ThreadPoolExecutor` timeout with automatic procedural fallback.
   - *What to say:* "Notice the model tag reads `Template` rather than `Gemini`. Our system features air-gapped resilience: if an external LLM provider experiences network latency or rate limits, the concierge automatically formats a procedural dispatch so estate operations are never blocked."

2. **Accidental Double Click:**
   - *Built-in defense:* Both the "Launch Attack" and "Reset demo" buttons have double-click prevention that disables them while requests are in flight.

3. **Accidental Page Refresh or Tab Switch:**
   - *Built-in defense:* The WebSocket endpoint replays the last 30 seconds of telemetry, active incident status, Bayes gauge, STRIPS plan, and GenAI report upon reconnection, with automatic tab-visibility wake-up listeners.

4. **Port 8000 Conflict:**
   - Run: `venv/bin/uvicorn app:app --port 8001 --reload`

---

## 5 Likely Teacher / Evaluator Questions & Answers

### Q1: "Why did you use Forward Chaining Horn Clauses for Module 4 instead of simple if-else statements or a machine learning classifier?"
> **Answer:** "Forward chaining over Horn clauses provides explainable, deterministic deduction with formal proof guarantees. In cybersecurity and safety-critical environments, black-box classifiers can hallucinate or suffer from adversarial drift. Horn clauses ensure that every deduction is transparent, monotonic, and produces an auditable proof trace that non-technical estate managers can understand."

### Q2: "How does the Bayes engine avoid floating-point underflow and handle feature dependencies?"
> **Answer:** "Module 5 uses the **odds form** of Bayes' Rule: posterior odds = prior odds × likelihood ratios. Multiplying likelihood ratios directly avoids repetitive marginal probability denominator calculations. Furthermore, treating packet size, SYN flags, and source rate as conditionally independent Naive Bayes features allows rapid, lightweight computation that runs in sub-millisecond time without floating-point degradation."

### Q3: "In Module 6, how do you prevent the STRIPS planner from exploring infinite paths or selecting irrelevant actions?"
> **Answer:** "The planner uses **breadth-first forward search (BFS)** over a state space defined by immutable `frozensets` of propositions, with a visited-state cache to prevent cycles. Distractor actions like `rate_limit_port` or `notify_admin` cannot satisfy the dual goal condition `{'threat_blocked', 'block_verified'}` without adding unnecessary depth, ensuring BFS always discovers the optimal minimal 3-step path."

### Q4: "How do you protect against prompt injection or malicious data leaking into the LLM report?"
> **Answer:** "First, the Gemini API is called strictly backend-to-backend with parameterized factual inputs (time, classification, source IP, probability, and action sequence). Second, all client rendering strictly uses `textContent` and DOM nodes rather than `innerHTML` to prevent script injection. Finally, `GEMINI_API_KEY` is loaded securely via environment variables and is never transmitted to the browser or written to logs."

### Q5: "What prevents the background telemetry loop from crashing if an unhandled packet or database lock occurs?"
> **Answer:** "The 1-second simulator worker runs within an isolated asyncio task supervised by FastAPI's lifespan context. All tick generation, detection logic, and broadcast operations are wrapped in resilient top-level exception handlers that log anomalies while allowing the loop to maintain uninterrupted cadence. Additionally, SQLite connections utilize WAL mode and immediate parameterized execution."
