# Linux Dosya Şifreleme Aracı (PyQt6)

Bu araç, kullanıcıların dosyalarını farklı şifreleme yöntemleriyle güvenli bir şekilde şifreleyip çözmesini sağlayan bir **Linux uyumlu GUI** uygulamasıdır. **PyQt6** tabanlı arayüzü sayesinde kullanıcı dostu bir deneyim sunar.

## 🚀 Özellikler

- **Modern Arayüz:** PyQt6 ile tasarlanmış kolay kullanılabilir GUI.
- **Çoklu Şifreleme Yöntemi:**
  - **Base64 (Düşük Güvenlik)**
  - **XOR (Orta Güvenlik)**
  - **AES-256 (Yüksek Güvenlik)**
  - **RSA-2048 (Çok Yüksek Güvenlik)**
- **Dosya Seçme & Şifreleme & Deşifreleme:**
  - Kullanıcı istediği dosyayı seçip **şifreleyebilir veya çözüp tekrar erişebilir.**
- **Çoklu İş Parçacığı (Threading):**
  - **Büyük dosyalar işlenirken arayüz donmaz, stabil çalışır.**
- **Tüm Linux Dağıtımlarıyla Uyumlu:**
  - Ubuntu, Debian, Fedora, Arch Linux ve diğer Linux sistemlerinde sorunsuz çalışır.

## 🛠️ Kurulum

Python ve bağımlılıkları yükleyin:

```bash
sudo apt update && sudo apt install python3 python3-pip -y
pip install pyqt6 pycryptodome
```

Kod dosyasını indirin:

```bash
git clone https://github.com/kullanici_adiniz/sifreleme-araci.git
cd sifreleme-araci
```

### 📌 Çalıştırma

```bash
python3 main.py
```

## 📌 Kullanım

1. **"📂 Dosya Seç"** butonu ile bir dosya seçin.
2. **Şifreleme yöntemini** seçin (Base64, XOR, AES-256, RSA-2048).
3. **Şifreleme anahtarınızı** girin.
4. **"🔒 Dosyayı Şifrele"** butonuna basarak şifreleyin.
5. **"🔓 Dosyayı Deşifre Et"** butonuna basarak çözümleyin.

## 🐜 Lisans

Bu proje **MIT Lisansı** ile korunmaktadır. Kullanım serbesttir!
