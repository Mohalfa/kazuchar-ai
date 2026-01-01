# 🎭 KazuChar.AI v10 - Bootstrap 5 Edition

Platform AI Character Roleplay dengan Bootstrap 5 UI Modern

## 🚀 Deploy ke Render.com

### Langkah-langkah Deploy:

#### Step 1: Upload ke GitHub

1. Buat akun GitHub jika belum punya: https://github.com
2. Klik **"New repository"** 
3. Nama repository: `kazuchar-ai`
4. Pilih **Public** atau **Private**
5. Klik **"Create repository"**
6. Upload semua file dari folder ini ke repository

**Cara upload file:**
- Klik **"uploading an existing file"** 
- Drag & drop semua file
- Klik **"Commit changes"**

#### Step 2: Deploy di Render

1. Buka https://dashboard.render.com
2. Login/Daftar dengan GitHub
3. Klik **"+ New"** → **"Web Service"**
4. Klik **"Connect a repository"**
5. Authorize Render untuk akses GitHub
6. Pilih repository `kazuchar-ai`

#### Step 3: Konfigurasi

Isi form:
- **Name:** `kazuchar-ai` (atau nama lain)
- **Region:** Singapore (terdekat)
- **Branch:** `main`
- **Runtime:** `Node`
- **Build Command:** `npm install`
- **Start Command:** `npm start`
- **Plan:** `Free`

#### Step 4: Environment Variables (Klik "Advanced")

Tambahkan:
| Key | Value |
|-----|-------|
| RENDER | true |
| JWT_SECRET | (klik Generate) |

#### Step 5: Deploy

1. Klik **"Create Web Service"**
2. Tunggu 3-5 menit
3. Setelah selesai, klik URL yang diberikan

---

## 🔐 Login Default

```
Email: admin@kazuchar.ai
Password: admin123
```

---

## ⚠️ Catatan Penting (Free Tier)

1. **Data tidak permanen** - Database dan upload akan reset saat service restart
2. **Sleep mode** - Service tidur setelah 15 menit tidak aktif
3. **Untuk production**, gunakan PostgreSQL dan Cloudinary

---

## ✨ Fitur v10

- Bootstrap 5.3.2 dark theme
- Multi-language (ID/EN)  
- Character management
- Live chat support
- Token system
- NSFW access control
- Mobile responsive

---

## 💻 Development Lokal

```bash
npm install
npm start
# Buka http://localhost:3000
```

---

MIT License | KazuChar.AI
