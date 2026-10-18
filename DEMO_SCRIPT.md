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

### 0:25 – 0:50 · Perimeter Intrusion & Logic Engine (Module 4)
- **What to Click:** Click the **"Launch Attack"** button in the hero panel.
- **What to Say:**
  > "I've triggered a simulated volumetric SYN-flood from an external IP (`203.0.113.99`). Immediately, the telemetry spikes to 45 packets per second and shifts to terracotta. Without human intervention, our Module 4 logic engine analyzes the rolling window and executes forward-chaining Horn clause deduction. In Column I, you see its mathematical proof trace: deriving high SYN rate and single target port, proving it is a DDoS, and concluding malicious intent."
- **What the Audience Sees:**
  - Real-time line chart spikes to ~45 pps and shifts to terracotta (`#B5654A`).
  - Hero status changes to *"A disturbance at the gate..."*.
  - Cover Story panel illuminates with the attacker IP and timestamp.
  - Column I ("Recognition") streams: *"I know this one: DDoS"* with a 400ms staggered proof trace.

---

### 0:50 – 1:15 · Bayesian Probability & Defense Planning (Modules 5 & 6)
- **What to Say:**
  > "Next, Module 5 applies Bayes' Rule in odds formulation. Starting from a skeptical 5% prior, it updates odds across packet size, SYN flags, and source rate, calculating a 95% posterior probability of malice shown on our radial gauge. Immediately following, Module 6—our automated STRIPS planner—conducts a breadth-first forward search over possible actions to synthesize a verifiable 3-step containment plan: identifying the source IP, adding the firewall rule, and verifying packet cessation."
- **What the Audience Sees:**
  - Column II ("Probability") animates an SVG gauge up to 95%, displaying the 4-step odds multiplication breakdown.
  - Column III ("The Plan") renders the 3-step action sequence, ticking off steps with completion rings.

---

### 1:15 – 1:45 · Autonomous Defense, Quiet Resolution & GenAI Report
- **What to Say:**
  > "Now watch the telemetry chart: the planner executes the defense, blocking the attacker IP at the perimeter boundary. Packets drop immediately back to baseline calm. Concurrently, our GenAI integration synthesizes an understated, polite incident report in the voice of a private estate concierge. Notice the drop cap, serif typography, and pull quote—informing estate managers without panic."
- **What the Audience Sees:**
  - Telemetry chart drops from 45 pps back to ~5 pps; color shifts back to serene olive.
  - Hero status updates to: *"Threat blocked. All quiet on the network."*
  - Cover story displays a calm olive `Resolved` badge.
  - Magazine Feature populates with a 3-paragraph editorial dispatch tagged `Gemini` (or `Template`).

---

### 1:45 – 2:00 · Archival Memory & The Reset Ritual
- **What to Click:** Scroll to **"Back Issues"** at the bottom, expand the newest accordion item, then scroll back up and click **"Reset demo"**.
- **What to Say:**
  > "Every resolved incident is permanently recorded in SQLite under 'Back Issues' with full probabilities and audit trails. When our shift ends, clicking 'Reset demo' clears the firewall blocklist and resets the live simulation state while safely preserving the historical archive. That is The Agency: autonomous intelligence delivering unseen sanctuary."
- **What the Audience Sees:**
  - Expanding the accordion reveals the incident record, timestamp, probability badge, and defense sequence.
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
