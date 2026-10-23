# MannAutomatedScanner — Automated Web Security Scanner

> Audit any website for missing **secure headers** and **CORS misconfigurations** in seconds.
> Live on GitHub Pages — no server required.

---

## Live Demo

Once deployed, your site will be live at:
```
https://<your-github-username>.github.io/MannAutomatedScanner/
```

---

## Deploy to GitHub Pages (Step-by-Step)

### Step 1 — Create a GitHub repository

1. Go to [github.com](https://github.com) and log in
2. Click **New repository**
3. Name it: `MannAutomatedScanner`
4. Set it to **Public**
5. Click **Create repository**

### Step 2 — Push your code

Open a terminal in this folder and run:

```bash
git init
git add .
git commit -m "Initial commit — MannAutomatedScanner"
git branch -M main
git remote add origin https://github.com/<your-username>/MannAutomatedScanner.git
git push -u origin main
```

> Replace `<your-username>` with your actual GitHub username.

### Step 3 — Enable GitHub Pages

1. Go to your repository on GitHub
2. Click **Settings** → **Pages** (left sidebar)
3. Under **Source**, select **GitHub Actions**
4. Click **Save**

### Step 4 — Watch it deploy

1. Go to the **Actions** tab in your repository
2. You'll see the **Deploy to GitHub Pages** workflow running
3. Once it turns green ✅, your site is live!

### Step 5 — Visit your live site

```
https://<your-username>.github.io/MannAutomatedScanner/
```

---

## How the Live Scanner Works

The GitHub Pages version is **100% client-side** — no Python or server required.

The scan button:
1. Takes the URL you enter
2. Fetches it via [allorigins.win](https://allorigins.win) (a free CORS proxy)
3. Reads the response headers in JavaScript
4. Runs all 7 header checks + 6 CORS rules in the browser
5. Displays a scored report with recommendations

---

## Run Locally (Python)

```bash
# Install dependencies
pip install -r requirements.txt

# Terminal scanner
python scanner_ui.py https://example.com

# Web server (local only)
python app.py
# Open http://127.0.0.1:5000
```

---

## Project Structure

```
├── index.html               ← Frontend website (works standalone on GitHub Pages)
├── styles.css               ← Dark-mode stylesheet
├── MannAutomatedScanner.py  ← Python scanner core (CLI)
├── scanner_ui.py            ← Rich terminal UI
├── app.py                   ← Flask API server (local use)
├── requirements.txt         ← Python dependencies
├── README.md                ← This file
└── .github/
    └── workflows/
        └── deploy.yml       ← GitHub Actions auto-deploy workflow
```

---

## Security Notice

Only scan websites you **own** or have **explicit permission** to test.

---

## License

MIT — free to use, modify, and distribute.
