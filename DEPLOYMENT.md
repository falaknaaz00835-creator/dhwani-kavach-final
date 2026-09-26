# 🚀 Dhwani-Kavach Deployment & Auto-CI/CD Guide

Is guide me complete steps hain ki project ko kaise live deploy karein aur future me koi bhi change commit/push karne par **automatic deployment (Continuous Deployment / CI/CD)** kaise kaam karega.

---

## 🌟 Option 1: Render.com (Recommended - 100% Free & Auto-Deploy on Push)

Render sabse best aur simple option hai jisme aapka GitHub repository directly connect ho jata hai aur **har `git push` ke baad apne aap live update ho jata hai**.

### Step 1: Render par Account aur Repo Connect karein
1. [Render Dashboard](https://dashboard.render.com/) par jayein aur **GitHub se Sign In** karein.
2. Top-right me **`New +`** par click karein aur **`Web Service`** choose karein.
3. Apna repository select karein:  
   👉 `falaknaaz00835-creator/dhwani-kavach-final`
4. Render automatically `Dockerfile` ya `render.yaml` detect kar lega:
   - **Name**: `dhwani-kavach` (ya apni pasand ka naam)
   - **Region**: Singapore (India ke paas sabse lowest latency)
   - **Branch**: `main`
   - **Runtime**: `Docker`
   - **Instance Type**: `Free`
5. Bottom me **`Create Web Service`** par click kar dein!

### 🎉 Auto-Deployment Feature (Future Changes):
- Render me **`Auto-Deploy: Yes`** pehle se enabled hota hai.
- Aage jab bhi aap koi code edit karenge aur terminal me:
  ```bash
  git add .
  git commit -m "update feature xyz"
  git push origin main
  ```
  karenge, **Render automatically new commit ko pull karega, build karega aur live website update kar dega**! Aapko manually dubara deploy karne ki zaroorat nahi padegi.

---

## 🌟 Option 2: Hugging Face Spaces (SIH / Hackathon Evaluators ke liye)

Agar aapko AI/ML evaluators ke samne Hugging Face Space URL dikhana hai:
1. [Hugging Face New Space](https://huggingface.co/new-space) par jayein.
2. Space Name: `dhwani-kavach`
3. Space SDK: **Docker** (Blank) choose karein.
4. License: Apache 2.0 ya MIT choose karein aur Space create karein.
5. GitHub repository ke code ko Hugging Face Space me push karne ke liye:
   ```bash
   git remote add hf https://huggingface.co/spaces/<YOUR_HF_USERNAME>/dhwani-kavach
   git push hf main
   ```
6. Hugging Face free 16 GB RAM provide karta hai aur automatic live link deta hai.

---

## 🌟 Option 3: Local Docker Run (Testing & Offline Demo)

Agar aapko offline presentation me bina internet ke full container run karna ho:
```bash
docker build -t dhwani-kavach .
docker run -p 8000:8000 dhwani-kavach
```
Ab browser me `http://localhost:8000` open karein.

---

## 🔄 GitHub Actions CI/CD Pipeline

Repo me `.github/workflows/ci.yml` set kiya gaya hai:
- Jab bhi aap koi bhi commit `main` branch me push karenge ya pull request banayenge:
  - GitHub Actions automatically saare tests (`pytest tests/ test_server_api.py`) run karega.
  - Model integrity aur inference pipeline verify karega.
  - Agar sab pass hota hai, to green checkmark ✅ show hoga.
