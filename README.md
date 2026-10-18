# The Agency — Boutique Cybersecurity Concierge

A cybersecurity monitoring dashboard styled like a serene, premium nature-retreat website instead of a dark hacker terminal. Warm cream surfaces, deep forest-green panels, elegant serif typography, big rounded corners, pill buttons, and inline botanical SVG line art.

## Stage 1 Architecture
- **Backend:** FastAPI, Uvicorn, SQLite (`agency.db`), bcrypt password hashing, Starlette `SessionMiddleware`
- **Database:** Auto-initialization with `users`, `incidents`, and `reports` tables, and automatic first-run agent seeding
- **Security:** Signed session cookies, in-memory IP rate limiting (5 attempts per 5 minutes)
- **Frontend:** Vanilla HTML5, CSS3 with custom properties, vanilla ES6 JavaScript (no build tools required)

---

## 1. Setup

### Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

### Install dependencies:
```bash
pip install -r requirements.txt
```

### Configure environment:
```bash
cp .env.example .env
```
Open `.env` and set `SESSION_SECRET` to any random string (e.g. `openssl rand -hex 32` or `retreat-sanctuary-key-secret-2026`).

---

## 2. Run Application

Start the local development server:
```bash
uvicorn app:app --reload
```

Then navigate in your browser to:
[http://127.0.0.1:8000](http://127.0.0.1:8000)

---

## 3. Default Login Credentials

On first run, the database automatically seeds the initial agent:
- **Username:** `agent001`
- **Password:** `olive-and-cream`
- **Display Name:** `Agent 001`

---

## 4. Run Tests

Execute the automated test suite with pytest:
```bash
pytest
```
