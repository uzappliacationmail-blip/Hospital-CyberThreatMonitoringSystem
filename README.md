# Hospital CTMS — hospital_ctms_enhanced

Brief: Hospital CTMS is a lightweight command & threat monitoring system (CTMS) developed for hospital network monitoring, anomaly detection, and analyst workflows. This repository contains the application, web UI, simple model serving, and test artifacts for the project.

Quickstart
1. Create and activate virtual environment (Windows PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
2. Initialize DB (if needed):
```powershell
python setup_db.py
```
3. Run the app:
```powershell
python start.py
```

Notes
- This repository currently contains a SQLite DB file (`hospital_ctms.db`) that is for local development only — consider removing it before sharing publicly.
- A `.gitignore` was added to exclude runtime artifacts and sensitive files.

Repository details
- Local repo path: see local clone
- Commit: replace with `git rev-parse HEAD` to get current commit

Recommendations before pushing to a public remote
- Remove or rotate any sensitive credentials or databases.
- Optionally large artifacts (models, datasets) should be placed in a release or a separate storage (S3, Git LFS).

If you want, I can add a license, CI workflow, and help you push to a GitHub remote — provide the remote URL and I will push the `main` branch for you.
