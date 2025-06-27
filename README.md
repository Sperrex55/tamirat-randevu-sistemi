# ⚙️ Teknoloji Randevu Sistemi

**Teknoloji Randevu Sistemi**, kullanıcıların teknikerlerle kolayca randevu almasını, teknikerlerin randevularını etkin bir şekilde yönetmesini ve yöneticilerin tüm sistemi kapsamlı şekilde denetlemesini sağlayan modern, kullanıcı dostu bir web uygulamasıdır. 

Dijitalleşen çağda randevu süreçlerini hızlandırarak zamandan ve iş gücünden tasarruf sağlar, müşteri memnuniyetini artırır.

---

## 🚀 Özellikler

### 👥 Kullanıcılar için
- 🔐 **Kayıt & Giriş:** E-posta, TC kimlik numarası ve telefon numarası ile hızlı ve güvenli kayıt/giriş işlemleri.
- 📅 **Randevu Oluşturma:** Kullanıcı dostu arayüz üzerinden ihtiyaç duyulan servisler için anında randevu talep etme.
- 🗂️ **Randevu Yönetimi:** Aktif ve geçmiş randevuları kolayca görüntüleyip, gerekirse düzenleme ve iptal yapabilme.
- 💬 **Mesajlaşma:** Teknikerlerle doğrudan iletişim kurarak randevu detaylarını netleştirme.
- 📢 **Duyurular:** Sistemden gönderilen güncellemeler ve önemli duyurulardan haberdar olma.

### 🛠️ Teknikerler için
- 🆕 **Kayıt & Giriş:** Uzmanlık alanları, deneyim ve iletişim bilgileri ile detaylı kayıt imkanı.
- 📋 **Randevu Yönetimi:** Kendilerine atanmış randevuları listeleme, onaylama, reddetme veya iptal etme seçenekleri.
- 💬 **Mesajlaşma:** Kullanıcılar ile anlık iletişim kurarak servis süreçlerini optimize etme.
- 📣 **Duyurular:** Teknik ekibe özel bildirileri takip ederek güncel kalma.

### 🧑‍💼 Yöneticiler için
- 🖥️ **Admin Paneli:** Kullanıcılar, teknikerler ve randevular üzerinde tam yetki ve denetim.
- 👥 **Kullanıcı Yönetimi:** Yeni kullanıcı ekleme, var olanları düzenleme veya silme.
- 🔧 **Tekniker Yönetimi:** Tekniker kayıtlarını onaylama, düzenleme veya silme işlemleri.
- 📰 **Duyuru Yönetimi:** Sistemde yayınlanacak duyuruları oluşturma, düzenleme ve kaldırma.
- 📊 **Raporlama & Takip:** Randevu ve kullanıcı hareketleri üzerine detaylı analiz ve raporlar.

---

## 🛠️ Kullanılan Teknolojiler

- 🐍 **Flask:** Hızlı ve esnek Python web framework'ü.
- 🗄️ **Flask-SQLAlchemy:** Veritabanı işlemlerinde ORM kullanımıyla kolay yönetim.
- 🔒 **Flask-Login:** Güvenli kullanıcı kimlik doğrulama ve oturum yönetimi.
- 💾 **SQLite:** Hafif, dosya tabanlı ve kurulumu kolay veritabanı.
- 🎨 **HTML5 & CSS3:** Modern ve duyarlı kullanıcı arayüzü tasarımı.
- ⚡ **JavaScript (ES6+):** Dinamik içerik ve kullanıcı etkileşimi için.
- 📱 **Bootstrap 5:** Mobil uyumlu, şık ve kullanıcı dostu ön yüz framework'ü.

---

## 🏗️ Kurulum & Başlangıç

### 📋 Gereksinimler
- Python 3.7+
- pip (Python paket yöneticisi)

### 🚦 Kurulum Adımları



1. **Gerekli paketleri yükleyin:**

```bash
pip install -r requirements.txt
```

2. **Veritabanını oluşturun:**

```bash
python
>>> from app import db
>>> db.create_all()
>>> exit()
```

3. **Uygulamayı başlatın:**

```bash
python app.py
```

4. **Tarayıcıda açın:**

```
http://127.0.0.1:5000
```

---

## 🎯 Kullanım

- 👤 **Kullanıcı Girişi:** TC kimlik ve şifre ile kolay giriş.
- 🛠️ **Tekniker Girişi:** Uzmanlıklarına göre hızlı erişim.
- 👨‍💼 **Admin Girişi:** Yetkili yönetici paneli erişimi.
- 📅 **Randevu İşlemleri:** Kolayca randevu oluşturma, düzenleme ve iptal.
- 💬 **Mesajlaşma:** Kullanıcı ve tekniker arasında anlık iletişim.
- 📢 **Duyurular:** Güncel servis ve sistem bilgilerine erişim.

---

## 🛠️ Geliştirici Notları

- **Kod yapısı** modülerdir, kolay genişletilebilir.
- **Veritabanı şeması** SQLAlchemy modelleri ile tanımlanmıştır.
- **Kimlik doğrulama** Flask-Login ile yönetilir.
- **Özelleştirme** için HTML/CSS/JS dosyaları `static` ve `templates` klasörlerinde bulunur.

---

## 📬 İletişim & Destek

Herhangi bir soru, öneri veya katkı için:  
📧 **Email:** [servisyonetimi50@gmail.com](mailto:servisyonetimi50@gmail.com)  


---


## 📂 Proje Dosya Yapısı

```

/tamirat-randevu-sistemi
│
├── 📝 app.py                      # Ana uygulama dosyası
├── 📦 requirements.txt            # Proje bağımlılıkları
├── 📄 README.md                   # Proje açıklaması ve talimatlar
├── 📁 instance                    # Gizli veritabanı klasörü
│   └── 💾 teknoloji.db            # SQLite veritabanı dosyası
│
├── 📁 static                      # Statik dosyalar (CSS, JS, Görseller)
│   ├── 🎨 about.css
│   ├── 🎨 admin_dashboard.css
│   ├── 🎨 base_admin.css
│   ├── 🎨 base_technician.css
│   ├── 🎨 base_user.css
│   ├── 🎨 contact.css
│   ├── 📸 images                  # Görseller
│   │   ├── 🖼️ anasayfa.jpg
│   │   ├── 🖼️ anasayfa1.jpg
│   │   ├── 🖼️ hakkımızda.jpg
│   │   ├── 🖼️ kayıt1.jpg
│   │   ├── 🖼️ loginklavye.png
│   │   └── 🖼️ teknikerlogin.webp
│   ├── 🎨 index.css
│   ├── 🎨 randevu_olustur.css
│   ├── 🎨 register_user.css
│   ├── 🎨 style.css
│   ├── 🎨 technician_active_appointments.css
│   ├── 🎨 user_appointments.css
│   └── 🎨 user_dashboard.css
│
└── 📁 templates                   # HTML şablonları
    ├── 📄 about.html
    ├── 📄 admin_dashboard.html
    ├── 📄 admin_duyuru_duzenle.html
    ├── 📄 admin_duyuru_ekle.html
    ├── 📄 appointment_history.html
    ├── 📄 base.html
    ├── 📄 base_admin.html
    ├── 📄 base_technician.html
    ├── 📄 base_user.html
    ├── 📄 change_password.html
    ├── 📄 contact.html
    ├── 📄 Create_Appointment.html
    ├── 📄 edit_technician.html
    ├── 📄 edit_user.html
    ├── 📄 edit_user_appointment.html
    ├── 📄 index.html
    ├── 📄 login_admin.html
    ├── 📄 login_technician.html
    ├── 📄 login_user.html
    ├── 📄 manage_appointments.html
    ├── 📄 manage_technicians.html
    ├── 📄 manage_users.html
    ├── 📄 randevu_olustur.html
    ├── 📄 register_admin.html
    ├── 📄 register_technician.html
    └── 📄 register_user.html


```

_**Not:** Bu proje, teknolojik servis randevu süreçlerini dijitalleştirip kolaylaştırmak amacıyla geliştirilmiştir. Kullanımda karşılaştığınız hataları veya geliştirme önerilerinizi çekinmeden paylaşabilirsiniz._
