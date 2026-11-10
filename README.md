# CyberGuardian Connect (Phases 1 to 6)

Sign in, connect a security web application (or upload a report), watch a live dashboard,
get an AI analysis of any incident, chat with an AI Copilot about your incidents and your company
playbooks, approve response actions, and download a PDF report.
Your connections are saved to your account.

```
Source (web app / file) -> Connector -> Common incident format -> Dashboard | AI analysis | PDF report
```

## Project layout

```
app.py                     Streamlit entry point (login, then tabs: Dashboard, Incident Analysis, AI Copilot, Knowledge Base, Connections)
ui/                        The screens
  dashboard.py             Live dashboard (auto-refreshing fragment)
  analysis.py              Incident details, AI analysis, PDF download
  auth.py                  Log in / sign up screen
  actions.py               Response actions: propose, approve or reject, audit history
  copilot.py               The AI Copilot chat tab
  knowledge.py             The Knowledge Base tab: upload, embed, delete, and try a search
  kb_access.py             Shared helper: builds and searches a user's playbook index
  connections.py           Add / test / sync / remove connections, demo tools
  sidebar.py               AI provider, key, model and auto-refresh settings
  state.py, style.py, incident_view.py
connectors/                Turn outside data into the common incident format
  models.py, base.py, rest_api.py, file_upload.py
security.py                Password hashing, validation, encryption of saved secrets
database.py                SQLite: users and per-user encrypted connections
dashboard_data.py          All dashboard calculations (pure Python)
ai_analysis.py             Prompt, model call and report parsing
ai_actions.py              Action proposals and the checks that stop made-up targets
retrieval.py               Chunking incidents and BM25 keyword search
copilot.py                 Copilot prompt building and answering
knowledge.py               Playbook loading, chunking, embeddings, vector search, hybrid search
report_pdf.py              PDF report (ReportLab)
source_app/                The simulated SOC platform (FastAPI)
sample_data/KnowledgeBase.txt   Example incident report for the file connector
sample_data/playbooks/     3 sample playbooks (ransomware, phishing, account compromise)
tests/                     145 tests, no web framework or API key needed
```

## Setup

```bash
python -m pip install -r requirements.txt
```

## Run the demo (two terminals, both from this folder)

Terminal 1, the simulated web app:
```bash
python -m uvicorn source_app.main:app --port 8000
```
API key: `demo-key-123` (change with the `SOURCE_API_KEY` environment variable).
Interactive API docs: http://localhost:8000/docs

Terminal 2, the app:
```bash
python -m streamlit run app.py
```

Then:
0. **Sign up** with a username and a password of at least 8 characters. You are signed in straight away.
1. **Connections** tab: add a REST API connection (default URL, key `demo-key-123`), Save and sync.
   Or upload `sample_data/KnowledgeBase.txt` with the File upload option.
2. **Dashboard** tab: threat level, counts, indicators, ATT&CK techniques, affected hosts, timeline.
3. **Sidebar**: choose Gemini or Groq and paste your API key.
4. **Incident Analysis** tab: pick an incident, press **Analyze with AI**, then **Download PDF report**.
5. **Knowledge Base** tab: press **Load the 3 sample playbooks**, or upload your own PDF, TXT or MD files.
6. Further down the Incident Analysis tab, **Response actions**: press **Suggest actions with AI**, then **Approve**
   or **Reject** each one. An approved action is sent to the connected platform, the incident's
   status changes to Contained, and the decision appears in the action history.

## Live demo

With auto-refresh on (sidebar), open **Connections > Demo tools** and press
**Create a new incident on the source**. Within the refresh interval the dashboard
updates by itself and a pop-up announces the new incident.

## Accounts and security

- **Passwords** are never stored. Each is stored as a salted PBKDF2-HMAC-SHA256 hash (600,000 iterations).
- **Login** gives the same message for an unknown user and a wrong password. After 5 wrong
  passwords an account is locked for 5 minutes.
- **Saved connections** (URL, API key, uploaded report) are encrypted with Fernet before they
  are written to the database. Each user can only load and delete their own.
- **Where things are stored:** `data/cyberguardian.db` (accounts and encrypted connections) and
  `data/secret.key` (the encryption key, created on first run). Both are listed in `.gitignore`.
  Never commit them. Deleting `secret.key` makes saved connections unreadable.
- **Your own key:** set the `CYBERGUARDIAN_SECRET_KEY` environment variable (or the same name in
  Streamlit secrets) to a Fernet key instead of using the key file. Create one with:
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- **Data folder:** set `CYBERGUARDIAN_DATA_DIR` to store the database somewhere else.
- **Sessions:** a browser refresh signs you out (there is no "remember me" cookie), then you sign in again.
- **Streamlit Community Cloud** has temporary storage: accounts and saved connections are lost
  when the app restarts. Fine for a demo, but a hosted database would be needed for real use.

## AI Copilot

A chat on the **AI Copilot** tab for questions such as "Which host has ransomware?" or
"What actions were taken on INC-2026-0003?".

- **How it works (retrieval-augmented generation):** each incident is split into small labelled chunks
  (overview, host and network, indicators, ATT&CK techniques, timeline, pieces of an uploaded report, and
  the response actions taken). For every question the most relevant chunks are found with BM25 keyword
  search and only those are sent to the model, together with a one-line overview of every incident.
- **Numbers come from code, not the model:** counts such as "how many active incidents" are computed
  by the app and given to the model, because language models are unreliable at counting.
- **Grounded and honest:** the model is told to answer only from that context and to say when the
  connected data does not contain the answer. Every answer lists the sources it used.
- **Read-only and injection-aware:** the Copilot cannot run actions, and it is told to treat incident
  text as data, so instructions hidden inside a report are not followed.
- **Focus and style:** focus on one incident or all of them; choose a "Simple explanation" style for
  newcomers or "Technical and concise" for experienced analysts.
- **No extra key or model:** it uses the same provider key as the analysis. Keyword search suits exact
  security terms (IPs, incident IDs, CVEs). Embedding-based search could be added later for meaning-based matching.
- The conversation lives in the browser session only and is cleared on logout.

## Knowledge base (RAG over playbooks, "what to do")

Incident data tells the app **what happened**; it is searched with BM25 (see the AI Copilot section
below). The **Knowledge Base** tab is a second, separate knowledge source for **what to do**: your
playbooks, procedures and policies. This is retrieval-augmented generation the way the first
CyberGuardian project used it, with embeddings and a vector index, now reused for playbooks instead of
incident reports, and combined with keyword search.

- **Pipeline:** a document -> pages -> chunks (about 1000 characters, preferring to break at headings or
  paragraphs) -> an embedding for each chunk (`gemini-embedding-001` by default) -> a vector index.
- **Hybrid search:** every question is searched two ways at once: by meaning (cosine similarity over the
  embeddings) and by keywords (the same BM25 as the Copilot). The two ranked lists are merged with
  reciprocal rank fusion, so a chunk that either method rates highly rises to the top.
- **FAISS, optional:** if the `faiss-cpu` package is installed (see `requirements.txt`), it is used to
  search the vectors faster; otherwise a numpy-based search gives the same results. Either way, this is
  the same "vectors + FAISS" idea as the first project, now optional rather than required.
- **No key, no crash:** with no Gemini key, or before a document is embedded, search falls back to
  keywords only and says so. A failed embedding call falls back the same way instead of breaking the page.
- **Used everywhere:** the AI analysis, the AI-suggested response actions, and the Copilot all search the
  playbooks for the incident (or question) and are told to follow and cite them, for example "Isolate the
  host [KB1]". The PDF report lists the playbook references used.
- **3 sample playbooks** (ransomware, phishing, account compromise) can be loaded with one click, so the
  feature works without needing your own documents.
- **Privacy:** creating embeddings sends your documents' text to Google. Use the samples or your own
  non-confidential documents for a demo.

## Response actions (human in the loop)

- The AI may suggest only three actions: block an IP address, isolate a host, disable a user account.
- **Every suggestion is checked against the incident's own data.** A target that does not appear in the
  incident (an invented IP, another host) is dropped, internal IP addresses can never be blocked, and
  duplicates are removed. The screen tells you how many suggestions were dropped.
- **Nothing is executed without a click.** Approve sends the action to the connected platform
  (`POST /api/v1/actions`); Reject sends nothing.
- **Advisory only for uploaded files:** an incident from a file has no platform behind it, so its
  suggestions cannot be executed.
- **Audit log:** every approve and reject is stored with who decided, when, what was proposed (by the AI
  or by rules), and the result. It is shown per incident under "Action history".
- **Without AI:** "Suggest actions without AI" uses simple rules on the incident data, so the feature
  still works with no API key.

## Keys

Keys are typed in the sidebar and live only in the browser session. When you deploy,
you can instead put `GEMINI_API_KEY` and/or `GROQ_API_KEY` in Streamlit secrets
(a key typed in the sidebar wins over a secret).

## Tests

```bash
python -m unittest discover -s tests -v
```

## Notes

- The AI works from the incident's data (and a capped excerpt of an uploaded report).
  It needs only one key: the chosen provider's.
- Connections live in the Streamlit session for now (lost on refresh). The accounts
  phase moves them to a database with encrypted API keys.
- Auto-refresh updates the Dashboard tab. The Incident Analysis tab picks up new
  incidents the next time you interact with the page.
- The API key is sent in the `X-API-Key` header. Use HTTPS for any real deployment.
