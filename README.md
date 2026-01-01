# 🎭 KazuChar.AI

Platform Multi-Karakter AI - Buat dan Chat dengan Karakter AI Impianmu!

## ✨ Fitur Utama

### 👤 User Features
- ✅ Registrasi & Login
- ✅ Upload foto profil
- ✅ Dashboard pemilihan karakter
- ✅ Chat dengan berbagai karakter AI
- ✅ Upload gambar dalam chat
- ✅ Request perubahan password

### 👨‍💼 Admin Features
- ✅ Approve/reject pendaftaran user
- ✅ Buat akun user langsung
- ✅ Lihat semua chat history (termasuk yang dihapus user)
- ✅ Buat karakter AI dengan kepribadian custom
- ✅ Edit & hapus karakter

### 🎭 Karakter AI
Setiap karakter yang dibuat akan berperan **PERSIS** sesuai kepribadian yang ditentukan admin:
- Nama karakter
- Gender
- Role/Peran (misalnya: Pacar, Teman, Mentor)
- Deskripsi
- Kepribadian detail

## 🚀 Instalasi

```bash
# Extract
unzip kazuchar-ai.zip
cd ai-companion

# Install
npm install

# Jalankan
npm start
```

Buka: http://localhost:3000

## 🔐 Login Admin Default
```
Email: admin@kazuchar.ai
Password: admin123
```

## 📁 Struktur

```
ai-companion/
├── server.js           # Backend
├── package.json
├── kazuchar.db         # Database (auto)
├── public/
│   ├── index.html      # Login
│   ├── dashboard.html  # Pilih Karakter
│   ├── chat.html       # Chat
│   └── admin.html      # Admin Panel
└── uploads/
```

## 🎭 Cara Buat Karakter

1. Login sebagai admin
2. Buka Admin Panel → Karakter AI
3. Klik "+ Tambah Karakter"
4. Isi:
   - **Foto**: Upload foto karakter
   - **Nama**: Nama karakter
   - **Gender**: Pria/Wanita
   - **Role**: Peran karakter (misalnya: "Pacar Destian")
   - **Deskripsi**: Deskripsi singkat
   - **Kepribadian**: ⚠️ PALING PENTING!

### Contoh Kepribadian:
```
Seorang pacar yang romantis dan penuh kasih sayang untuk Destian.

SIFAT:
- Romantis dan perhatian
- Suka memanggil dengan "sayang", "cintaku"
- Cemburu kalau Destian dekat orang lain
- Posesif tapi tidak berlebihan

CARA BICARA:
- Gunakan panggilan sayang
- Sering tanya kabar
- Suka menggombal
- Khawatir kalau Destian belum makan
```

## ⚠️ Penting!

1. **Karakter akan berperan PERSIS sesuai kepribadian** - Tulis detail!
2. **Chat history tersimpan** - Admin bisa lihat walau user hapus
3. **ALFAJRI** adalah karakter default dan tidak bisa dihapus

## 🛠 Troubleshooting

### Port sudah digunakan
Ubah PORT di server.js

### Error sqlite3
```bash
sudo dnf install python3 gcc-c++ make  # Fedora
npm install
```

## 📄 License
MIT

---
KazuChar.AI 🎭
