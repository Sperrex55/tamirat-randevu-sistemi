from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user as login_user_func, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_
from datetime import datetime
from flask_login import login_required
import re
from flask import session, redirect, url_for
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'gelistirme_anahtari'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///teknoloji.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'  # Login gerekli sayfalarda buraya yönlendirme yapılacak

# MODELLER
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    ad = db.Column(db.String(50), nullable=False)
    soyad = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    tc = db.Column(db.String(11), unique=True, nullable=False)
    telefon = db.Column(db.String(11), unique=True, nullable=False)
    dogum_tarihi = db.Column(db.Date, nullable=False)
    cinsiyet = db.Column(db.String(10), nullable=False)
    konum = db.Column(db.String(50))
    sifre = db.Column(db.String(255), nullable=False)
    kayit_tarihi = db.Column(db.DateTime, default=datetime.utcnow)

    def get_id(self):
        return f"user-{self.id}"

class Technician(UserMixin, db.Model):
    __tablename__ = 'technicians'
    id = db.Column(db.Integer, primary_key=True)
    ad = db.Column(db.String(50), nullable=False)
    soyad = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    telefon = db.Column(db.String(11), unique=True, nullable=False)
    tc = db.Column(db.String(11), unique=True, nullable=False)
    dogum_tarihi = db.Column(db.Date, nullable=False)
    uzmanlik = db.Column(db.String(100), nullable=False)
    destek_modeli = db.Column(db.String(50), nullable=False)
    tecrube = db.Column(db.Integer, nullable=False)
    konum = db.Column(db.String(50))
    referans = db.Column(db.Text)
    ek_yetenekler = db.Column(db.Text)
    sifre = db.Column(db.String(255), nullable=False)
    kayit_tarihi = db.Column(db.DateTime, default=datetime.utcnow)
    onay = db.Column(db.Boolean, default=False)    # Tekniker onayı
    iptal = db.Column(db.Boolean, default=False)   # Tekniker iptal durumu

    def get_id(self):
        return f"tech-{self.id}"


class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    technician_id = db.Column(db.Integer, db.ForeignKey('technicians.id'), nullable=True)
    date = db.Column(db.Date, nullable=False)
    uzmanlik = db.Column(db.String(100), nullable=False)
    destek_modeli = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Beklemede')

    # İlişkiler
    user = db.relationship('User', backref='appointments')
    technician = db.relationship('Technician', backref='appointments')  # Tekniker ilişkisi tanımlı


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    technician_id = db.Column(db.Integer, db.ForeignKey('technicians.id'), nullable=False)
    subject = db.Column(db.String(150), nullable=False)
    body = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('received_messages', lazy=True))
    technician = db.relationship('Technician', backref=db.backref('sent_messages', lazy=True))

    def __repr__(self):
        return f'<Message {self.subject} from Technician {self.technician_id} to User {self.user_id}>'


class Admin(UserMixin, db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    tc = db.Column(db.String(11), unique=True, nullable=False)
    ad = db.Column(db.String(50), nullable=False)
    soyad = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    sifre = db.Column(db.String(255), nullable=False)
    kayit_tarihi = db.Column(db.DateTime, default=datetime.utcnow)

    def get_id(self):
        return f"admin-{self.id}"


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    target_group = db.Column(db.String(20), nullable=False)  # 'tekniker' veya 'uye'


@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith("user-"):
        return User.query.get(int(user_id[5:]))
    elif user_id.startswith("tech-"):
        return Technician.query.get(int(user_id[5:]))
    elif user_id.startswith("admin-"):
        return Admin.query.get(int(user_id[6:]))
    return None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')

# Login ve Register seçim
@app.route('/login', methods=['POST'])
def choose_login():
    role = request.form.get('role')
    if role == "technician":
        return redirect(url_for('technician_login'))
    elif role == "user":
        return redirect(url_for('user_login'))
    flash('Lütfen bir kullanıcı türü seçiniz.', 'warning')
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def choose_register():
    role = request.form.get('role')
    if role == "technician":
        return redirect(url_for('register_technician'))
    elif role == "user":
        return redirect(url_for('register_user'))
    flash('Lütfen bir kullanıcı türü seçiniz.', 'warning')
    return redirect(url_for('index'))

# Kullanıcı Giriş
@app.route('/login_user', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        tc = request.form.get('tc')
        sifre = request.form.get('sifre')

        if not tc or not sifre:
            flash('Lütfen tüm alanları doldurun.', 'warning')
            return redirect(url_for('user_login'))

        user = User.query.filter_by(tc=tc).first()
        if user and check_password_hash(user.sifre, sifre):
            login_user_func(user)
            flash('Giriş başarılı!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Hatalı TC veya şifre!', 'danger')
            return redirect(url_for('user_login'))

    return render_template('login_user.html')

@app.route('/login_technician', methods=['GET', 'POST'])
def technician_login():
    if request.method == 'POST':
        tc = request.form.get('tc')
        sifre = request.form.get('sifre')

        tekniker = Technician.query.filter_by(tc=tc).first()
        if tekniker:
            if tekniker.iptal:
                flash('Tekniker hesabınız iptal edilmiştir. Sisteme giriş yapamazsınız.', 'danger')
                return redirect(url_for('technician_login'))

            if not tekniker.onay:
                flash('Tekniker hesabınız henüz onaylanmadı. Lütfen yönetici ile iletişime geçin.', 'warning')
                return redirect(url_for('technician_login'))

            if check_password_hash(tekniker.sifre, sifre):
                login_user_func(tekniker)
                flash('Tekniker girişi başarılı!', 'success')
                return redirect(url_for('technician_dashboard'))

        flash('Hatalı TC veya şifre!', 'danger')
        return redirect(url_for('technician_login'))

    return render_template('login_technician.html')



@app.route('/logout')
def logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('index'))

# USER KAYIT
@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        ad = request.form.get('ad')
        soyad = request.form.get('soyad')
        email = request.form.get('email')
        tc = request.form.get('tc')
        telefon = request.form.get('telefon')
        dogum_tarihi = request.form.get('dogumTarihi')
        cinsiyet = request.form.get('cinsiyet')
        konum = request.form.get('konum')
        sifre = request.form.get('sifre')
        sifre_onay = request.form.get('sifreOnay')

        # Temel alanların boş olmaması
        required_fields = [ad, soyad, email, tc, telefon, dogum_tarihi, cinsiyet, sifre, sifre_onay]
        if any(field is None or field.strip() == '' for field in required_fields):
            flash('Lütfen tüm zorunlu alanları doldurun!', 'danger')
            return redirect(url_for('register_user'))

        # Şifre eşleşme kontrolü
        if sifre != sifre_onay:
            flash('Şifreler eşleşmiyor!', 'danger')
            return redirect(url_for('register_user'))

        # TC ve Telefon 11 haneli ve sadece rakam olmalı
        if not (tc.isdigit() and len(tc) == 11):
            flash('TC Kimlik numarası 11 haneli olmalı!', 'danger')
            return redirect(url_for('register_user'))

        if not (telefon.isdigit() and len(telefon) == 11):
            flash('Telefon numarası 11 haneli olmalı!', 'danger')
            return redirect(url_for('register_user'))

        # Email format kontrolü (basit regex)
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            flash('Geçerli bir email adresi giriniz!', 'danger')
            return redirect(url_for('register_user'))

        # Email, TC veya telefon daha önce kayıtlı mı kontrol et (User ve Technician tablosunda)
        if User.query.filter(or_(User.email == email, User.tc == tc, User.telefon == telefon)).first() or \
           Technician.query.filter(or_(Technician.email == email, Technician.tc == tc, Technician.telefon == telefon)).first():
            flash('Bu bilgilerle kullanıcı zaten var!', 'danger')
            return redirect(url_for('register_user'))

        # Doğum tarihi parse ve yaş kontrol
        try:
            dogum_tarihi_obj = datetime.strptime(dogum_tarihi, '%Y-%m-%d')
        except ValueError:
            flash('Doğum tarihi formatı hatalı!', 'danger')
            return redirect(url_for('register_user'))

        today = datetime.today()
        age = today.year - dogum_tarihi_obj.year - ((today.month, today.day) < (dogum_tarihi_obj.month, dogum_tarihi_obj.day))
        if age < 18:
            flash('18 yaşından küçükler kayıt olamaz!', 'danger')
            return redirect(url_for('register_user'))

        sifre_hash = generate_password_hash(sifre)

        yeni_user = User(
            ad=ad,
            soyad=soyad,
            email=email,
            tc=tc,
            telefon=telefon,
            dogum_tarihi=dogum_tarihi_obj,
            cinsiyet=cinsiyet,
            konum=konum,
            sifre=sifre_hash
        )

        db.session.add(yeni_user)
        db.session.commit()

        flash('Kayıt başarılı!', 'success')
        return redirect(url_for('user_login'))

    return render_template('register_user.html')


# TECHNICIAN KAYIT
@app.route('/register_technician', methods=['GET', 'POST'])
def register_technician():
    if request.method == 'POST':
        ad = request.form.get('ad')
        soyad = request.form.get('soyad')
        email = request.form.get('email')
        telefon = request.form.get('telefon')
        tc = request.form.get('tc')
        dogum_tarihi = request.form.get('dogumTarihi')
        uzmanlik = request.form.get('uzmanlik')
        destek_modeli = request.form.get('destek_modeli')
        tecrube = request.form.get('tecrube')
        konum = request.form.get('konum')
        referans = request.form.get('referans')
        ek_yetenekler = request.form.get('ek_yetenekler')
        sifre = request.form.get('sifre')
        sifre_onay = request.form.get('sifreOnay')

        # Temel alanların boş olmaması
        required_fields = [ad, soyad, email, telefon, tc, dogum_tarihi, uzmanlik, destek_modeli, tecrube, konum, sifre, sifre_onay]
        if any(field is None or field.strip() == '' for field in required_fields):
            flash('Lütfen tüm zorunlu alanları doldurun!', 'danger')
            return redirect(url_for('register_technician'))

        # Tecrübe sayısal mı
        if not tecrube.isdigit():
            flash('Tecrübe yılı sayısal bir değer olmalıdır!', 'danger')
            return redirect(url_for('register_technician'))
        tecrube = int(tecrube)

        # Şifre eşleşme kontrolü
        if sifre != sifre_onay:
            flash('Şifreler eşleşmiyor!', 'danger')
            return redirect(url_for('register_technician'))

        # TC ve Telefon 11 haneli ve sadece rakam olmalı
        if not (tc.isdigit() and len(tc) == 11):
            flash('TC Kimlik numarası 11 haneli olmalı!', 'danger')
            return redirect(url_for('register_technician'))

        if not (telefon.isdigit() and len(telefon) == 11):
            flash('Telefon numarası 11 haneli olmalı!', 'danger')
            return redirect(url_for('register_technician'))

        # Email format kontrolü (basit regex)
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            flash('Geçerli bir email adresi giriniz!', 'danger')
            return redirect(url_for('register_technician'))

        # Email, TC veya telefon daha önce kayıtlı mı kontrol et (Her iki tabloda)
        if Technician.query.filter(or_(Technician.email == email, Technician.tc == tc, Technician.telefon == telefon)).first() or \
           User.query.filter(or_(User.email == email, User.tc == tc, User.telefon == telefon)).first():
            flash('Bu bilgilerle tekniker zaten var!', 'danger')
            return redirect(url_for('register_technician'))

        # Doğum tarihi parse ve yaş kontrol
        try:
            dogum_tarihi_obj = datetime.strptime(dogum_tarihi, '%Y-%m-%d')
        except ValueError:
            flash('Doğum tarihi formatı hatalı!', 'danger')
            return redirect(url_for('register_technician'))

        today = datetime.today()
        age = today.year - dogum_tarihi_obj.year - ((today.month, today.day) < (dogum_tarihi_obj.month, dogum_tarihi_obj.day))
        if age < 18:
            flash('18 yaşından küçükler kayıt olamaz!', 'danger')
            return redirect(url_for('register_technician'))

        # Konum zorunlu kontrol
        if not konum or konum.strip() == "":
            flash('Konum bilgisi zorunludur!', 'danger')
            return redirect(url_for('register_technician'))

        sifre_hash = generate_password_hash(sifre)

        yeni_technician = Technician(
            ad=ad,
            soyad=soyad,
            email=email,
            telefon=telefon,
            tc=tc,
            dogum_tarihi=dogum_tarihi_obj,
            uzmanlik=uzmanlik,
            destek_modeli=destek_modeli,
            tecrube=tecrube,
            konum=konum,
            referans=referans,
            ek_yetenekler=ek_yetenekler,
            sifre=sifre_hash
        )

        try:
            db.session.add(yeni_technician)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Kayıt sırasında hata oluştu: {str(e)}', 'danger')
            return redirect(url_for('register_technician'))

        flash('Tekniker kaydı başarılı!', 'success')
        return redirect(url_for('technician_login'))

    return render_template('register_technician.html')


@app.route('/user/dashboard')
@login_required
def user_dashboard():
    # Sadece User tipi için izin ver
    if not current_user.get_id().startswith("user-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    # Kullanıcının toplam randevu sayısını al
    total_appointments = Appointment.query.filter_by(user_id=current_user.id).count()

    # Kullanıcıya ait aktif duyuruları getir (varsa)
    announcements = Announcement.query.filter_by(target_group='uye').order_by(Announcement.date_created.desc()).all()

    return render_template('user_dashboard.html',
                           user=current_user,
                           total_appointments=total_appointments,
                           announcements=announcements)

@app.route('/randevu/olustur', methods=['GET', 'POST'])
@login_required
def randevu_olustur():
    if not current_user.get_id().startswith("user-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        date_str = request.form.get('date')
        uzmanlik = request.form.get('uzmanlik')
        destek_modeli = request.form.get('destek_modeli')
        category = request.form.get('category')
        description = request.form.get('description')

        # Validasyonlar
        if not all([date_str, uzmanlik, destek_modeli, category, description]):
            flash('Lütfen tüm alanları doldurun.', 'warning')
            return redirect(url_for('randevu_olustur'))

        try:
            appointment_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            if appointment_date < datetime.now().date():
                flash('Geçmiş tarih seçilemez.', 'warning')
                return redirect(url_for('randevu_olustur'))
        except ValueError:
            flash('Geçersiz tarih formatı.', 'warning')
            return redirect(url_for('randevu_olustur'))

        # Direkt randevuyu oluştur, tekniker ataması yapma (tekniker_id None)
        new_appointment = Appointment(
            user_id=current_user.id,
            technician_id=None,
            date=appointment_date,
            uzmanlik=uzmanlik,
            destek_modeli=destek_modeli,
            category=category,
            description=description,
            status='Tekniker Bekliyor'  # Atama yapılmadıysa bu statü
        )

        db.session.add(new_appointment)
        db.session.commit()

        flash('Randevunuz başarıyla oluşturuldu. En Kısa Sürede Onaylancaktır.', 'success')
        return redirect(url_for('user_dashboard'))

    current_date = datetime.now().strftime('%Y-%m-%d')
    return render_template('randevu_olustur.html', current_date=current_date)

@app.route('/user/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Mevcut şifre doğru mu kontrol et
        if not check_password_hash(current_user.sifre, current_password):
            flash('Mevcut şifre yanlış.', 'danger')
            return redirect(url_for('change_password'))

        # Yeni şifre doğrulaması
        if new_password != confirm_password:
            flash('Yeni şifre ile onayı uyuşmuyor.', 'warning')
            return redirect(url_for('change_password'))

        if len(new_password) < 6:
            flash('Şifre en az 6 karakter olmalıdır.', 'warning')
            return redirect(url_for('change_password'))

        # Şifreyi hashleyip kaydet
        current_user.sifre = generate_password_hash(new_password)
        db.session.commit()

        flash('Şifreniz başarıyla güncellendi.', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('change_password.html')

@app.route('/user/messages')
@login_required
def user_messages():
    if not current_user.get_id().startswith("user-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    # Örnek: sadece current_user.id'ye ait mesajları çek
    messages = Message.query.filter_by(user_id=current_user.id).order_by(Message.created_at.desc()).all()
    return render_template('user_messages.html', messages=messages)



def get_current_user_real_id():
    # Örn: "tech-5" veya "user-10" => 5 veya 10
    return int(current_user.get_id().split('-')[1])


@app.route('/technician/dashboard')
@login_required
def technician_dashboard():
    if not current_user.get_id().startswith("tech-"):
        flash("Bu sayfaya erişim yetkiniz yok.", "danger")
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()
    technician = Technician.query.get(technician_id)
    if not technician:
        flash('Teknisyen bilgisi bulunamadı.', 'danger')
        return redirect(url_for('index'))

    total_appointments = Appointment.query.filter_by(technician_id=technician_id).count()
    pending_appointments = Appointment.query.filter_by(technician_id=technician_id, status='Beklemede').count()
    completed_appointments = Appointment.query.filter_by(technician_id=technician_id, status='Tamamlandı').count()

    recent_appointments = Appointment.query.filter_by(technician_id=technician_id)\
                                           .order_by(Appointment.date.desc())\
                                           .limit(5).all()

    total_messages = Message.query.filter_by(technician_id=technician_id).count()

    # Tekniker duyuruları (limit 5 ile en yeni 5 duyuru)
    announcements = Announcement.query.filter_by(target_group='tekniker')\
                                      .order_by(Announcement.date_created.desc())\
                                      .limit(5).all()

    return render_template('technician_dashboard.html',
                           technician=technician,
                           total_appointments=total_appointments,
                           pending_appointments=pending_appointments,
                           completed_appointments=completed_appointments,
                           recent_appointments=recent_appointments,
                           total_messages=total_messages,
                           announcements=announcements)




@app.route('/technician/appointments')
@login_required
def technician_appointments():
    if not current_user.get_id().startswith("tech-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()
    technician = Technician.query.get(technician_id)
    if not technician:
        flash('Teknisyen bilgisi bulunamadı.', 'danger')
        return redirect(url_for('index'))

    appointments = Appointment.query.filter_by(technician_id=technician_id).order_by(Appointment.date.desc()).all()

    return render_template('technician_appointments.html', appointments=appointments, technician=technician)


@app.route('/technician/active_appointments')
@login_required 
def technician_active_appointments():
    if not current_user.get_id().startswith("tech-"):
        flash("Bu sayfaya erişim yetkiniz yok.", "danger")
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()
    
    # Sadece bu teknikerin uzmanlık alanındaki ve kendisine atanmış randevular
    appointments = Appointment.query.filter(
        (Appointment.technician_id == technician_id) |
        (
            (Appointment.technician_id.is_(None)) & 
            (Appointment.uzmanlik.ilike(f"%{current_user.uzmanlik}%"))
        )
    ).filter(
        Appointment.status.in_(['Beklemede', 'Tekniker Bekliyor'])
    ).order_by(Appointment.date.asc()).all()

    return render_template('technician_active_appointments.html', 
                         appointments=appointments,
                         current_user=current_user)



@app.route('/technician/messages')
@login_required
def technician_messages():
    if not current_user.get_id().startswith("tech-"):
        flash("Bu sayfaya erişim yetkiniz yok.", "danger")
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()
    messages = Message.query.filter_by(technician_id=technician_id).order_by(Message.created_at.desc()).all()

    return render_template('technician_messages.html', messages=messages)


@app.route('/user/appointments')
@login_required
def user_appointments():
    if not current_user.get_id().startswith("user-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    user_id = get_current_user_real_id()
    appointments = Appointment.query.filter_by(user_id=user_id).order_by(Appointment.date.desc()).all()

    return render_template('user_appointments.html', appointments=appointments)

@app.route('/user/appointment/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user_appointment(id):
    if not current_user.get_id().startswith("user-"):
        flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
        return redirect(url_for('index'))

    user_id = get_current_user_real_id()
    appointment = Appointment.query.get_or_404(id)

    if appointment.user_id != user_id:
        flash('Bu randevu size ait değil!', 'danger')
        return redirect(url_for('user_appointments'))

    if request.method == 'POST':
        appointment.date = datetime.strptime(request.form['date'], '%Y-%m-%dT%H:%M')
        appointment.uzmanlik = request.form['uzmanlik']
        appointment.category = request.form['category']
        appointment.description = request.form['description']

        db.session.commit()
        flash('Randevu başarıyla güncellendi.', 'success')
        return redirect(url_for('user_appointments'))

    return render_template('edit_user_appointment.html', appointment=appointment)


@app.route('/technician/appointment_history')
@login_required
def technician_appointment_history():
    if not current_user.get_id().startswith("tech-"):
        flash("Bu sayfaya erişim yetkiniz yok.", "danger")
        return redirect(url_for("index"))

    technician_id = get_current_user_real_id()
    page = request.args.get('page', 1, type=int)

    pagination = Appointment.query.filter_by(technician_id=technician_id)\
                                 .order_by(Appointment.date.desc())\
                                 .paginate(page=page, per_page=10, error_out=False)

    return render_template('technician_appointment_history.html',
                           appointments=pagination.items,
                           page=page,
                           total_pages=pagination.pages)


@app.route('/technician/approve/<int:appointment_id>', methods=['POST'])
@login_required
def approve_appointment(appointment_id):
    # 1. Kullanıcının tekniker olduğundan emin ol
    if not current_user.get_id().startswith("tech-"):
        flash("Bu işlem için tekniker yetkisi gerekiyor", "danger")
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()
    appointment = Appointment.query.get_or_404(appointment_id)
    
    print(f"Debug - Appointment Technician ID: {appointment.technician_id}, Current Technician ID: {technician_id}")  # Debug için

    # 2. Randevunun bu teknikere ait olduğunu veya atanmamış olduğunu kontrol et
    if appointment.technician_id is not None and appointment.technician_id != technician_id:
        flash("Bu randevuyu onaylama yetkiniz yok", "danger")
        return redirect(url_for('technician_active_appointments'))

    # 3. Eğer randevu atanmamışsa, bu teknikere ata
    if appointment.technician_id is None:
        appointment.technician_id = technician_id
    
    try:
        appointment.status = "Onaylandı"
        db.session.commit()
        flash("Randevu başarıyla onaylandı", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Onaylama sırasında hata oluştu: {str(e)}", "danger")
    
    return redirect(url_for('technician_active_appointments'))


@app.route('/technician/cancel/<int:appointment_id>', methods=['POST'])
@login_required
def cancel_appointment(appointment_id):
    # 1. Kullanıcının tekniker olduğundan emin ol
    if not current_user.get_id().startswith("tech-"):
        flash("Bu işlem için tekniker yetkisi gerekiyor.", "danger")
        return redirect(url_for('index'))

    technician_id = get_current_user_real_id()
    appointment = Appointment.query.get_or_404(appointment_id)

    # 2. Randevunun bu teknikere ait olduğunu kontrol et
    if appointment.technician_id is not None and appointment.technician_id != technician_id:
        flash('Bu randevuya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('technician_active_appointments'))

    # 3. Randevu iptal etme işlemi
    try:
        appointment.status = "İptal Edildi"
        db.session.commit()
        flash("Randevu başarıyla iptal edildi.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Hata oluştu: {str(e)}", "danger")

    return redirect(url_for('technician_active_appointments'))


@app.route('/api/user/appointments_status')
@login_required
def api_user_appointments_status():
    # Sadece user tipi kullanıcı erişebilir
    if not current_user.get_id().startswith("user-"):
        return {"error": "Yetkisiz erişim"}, 403

    user_id = get_current_user_real_id()

    appointments = Appointment.query.filter_by(user_id=user_id).order_by(Appointment.date.desc()).all()

    # JSON formatında döndürmek için liste oluştur
    data = []
    for appt in appointments:
        data.append({
            "id": appt.id,
            "date": appt.date.strftime('%d.%m.%Y'),
            "uzmanlik": appt.uzmanlik,
            "category": appt.category,
            "description": appt.description,
            "status": appt.status
        })

    return {"appointments": data}





@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        tc = request.form.get('tc')
        ad = request.form.get('ad')
        soyad = request.form.get('soyad')
        email = request.form.get('email')
        sifre = request.form.get('sifre')
        sifre_onay = request.form.get('sifreOnay')

        if not all([tc, ad, soyad, email, sifre, sifre_onay]):
            flash('Lütfen tüm alanları doldurun.', 'warning')
            return redirect(url_for('register_admin'))

        if sifre != sifre_onay:
            flash('Şifreler uyuşmuyor.', 'danger')
            return redirect(url_for('register_admin'))

        if Admin.query.filter((Admin.tc == tc) | (Admin.email == email)).first():
            flash('Bu TC veya Email zaten kayıtlı.', 'danger')
            return redirect(url_for('register_admin'))

        sifre_hash = generate_password_hash(sifre)

        yeni_admin = Admin(
            tc=tc,
            ad=ad,
            soyad=soyad,
            email=email,
            sifre=sifre_hash
        )

        db.session.add(yeni_admin)
        db.session.commit()

        flash('Admin başarıyla kaydedildi.', 'success')
        return redirect(url_for('index'))

    return render_template('register_admin.html')


# Admin login
@app.route('/login_admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        tc = request.form.get('tc')
        sifre = request.form.get('sifre')

        if not tc or not sifre:
            flash('Lütfen tüm alanları doldurun.', 'warning')
            return redirect(url_for('admin_login'))

        admin = Admin.query.filter_by(tc=tc).first()
        if admin and check_password_hash(admin.sifre, sifre):
            session['admin_id'] = admin.id
            flash('Admin girişi başarılı!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Hatalı TC veya şifre!', 'danger')
            return redirect(url_for('admin_login'))

    return render_template('login_admin.html')


# Admin dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash('Bu sayfaya erişmek için önce admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    admin = Admin.query.get(session['admin_id'])
    users = User.query.all()
    technicians = Technician.query.all()

    return render_template(
        'admin_dashboard.html',
        admin=admin,
        users=users,
        technicians=technicians
    )

# Admin logout
@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_id', None)
    flash('Başarıyla çıkış yapıldı.', 'success')
    return redirect(url_for('index'))


# Tekniker Onayla
@app.route('/admin/tekniker/onayla/<int:id>')
def onayla_tekniker(id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    tekniker = Technician.query.get_or_404(id)
    tekniker.onay = True
    db.session.commit()
    flash(f"{tekniker.ad} {tekniker.soyad} adlı tekniker onaylandı.", 'success')
    return redirect(url_for('admin_dashboard'))


# Tekniker İptal Et
@app.route('/admin/tekniker/iptal/<int:id>')
def iptal_tekniker(id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    tekniker = Technician.query.get_or_404(id)
    tekniker.iptal = True
    tekniker.onay = False
    db.session.commit()
    flash(f"{tekniker.ad} {tekniker.soyad} adlı tekniker iptal edildi ve sisteme giriş yapamaz.", 'success')
    return redirect(url_for('admin_dashboard'))


# Kullanıcı yönetimi
@app.route('/admin/manage_users')
def manage_users():
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    users = User.query.all()
    return render_template("manage_users.html", users=users)


# Tekniker yönetimi
@app.route('/admin/manage_technicians')
def manage_technicians():
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    technicians = Technician.query.all()
    return render_template("manage_technicians.html", technicians=technicians)


@app.route('/admin/manage_appointments')
def manage_appointments():
    # Admin giriş kontrolü
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))
    
    # Randevuları en yeni tarihe göre sırala
    appointments = Appointment.query.order_by(Appointment.date.desc()).all()
    
    return render_template("manage_appointments.html", appointments=appointments)

@app.route('/admin/appointment/cancel/<int:appointment_id>', methods=['POST'])
def admin_cancel_appointment(appointment_id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    appointment = Appointment.query.get_or_404(appointment_id)
    appointment.status = 'iptal'
    db.session.commit()
    flash('Randevu başarıyla iptal edildi.', 'success')
    return redirect(url_for('manage_appointments'))





@app.route('/user/edit/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.ad = request.form.get('ad')
        user.soyad = request.form.get('soyad')
        # diğer alanlar güncelle
        db.session.commit()
        flash('Kullanıcı bilgileri güncellendi.', 'success')
        return redirect(url_for('manage_users'))
    return render_template('edit_user.html', user=user)

@app.route('/admin/user/delete/<int:id>', methods=['POST'])
def delete_user(id):
    if 'admin_id' not in session:
        flash('Giriş yapmanız gerekiyor.', 'danger')
        return redirect(url_for('admin_login'))

    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash(f"{user.ad} {user.soyad} adlı kullanıcı silindi.", 'success')
    return redirect(url_for('manage_users'))



@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user_admin(user_id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.ad = request.form['ad']
        user.soyad = request.form['soyad']
        user.email = request.form['email']
        user.telefon = request.form.get('telefon', '')
        user.tc = request.form.get('tc', '')
        user.adres = request.form.get('adres', '')
        dogum_tarihi_str = request.form.get('dogum_tarihi', '')
        if dogum_tarihi_str:
            try:
                user.dogum_tarihi = datetime.strptime(dogum_tarihi_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Geçersiz doğum tarihi formatı.', 'warning')
                return render_template('edit_user.html', user=user)
        else:
            user.dogum_tarihi = None
        user.cinsiyet = request.form.get('cinsiyet', '')

        db.session.commit()
        flash('Kullanıcı bilgileri güncellendi.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user)

# Duyuru Ekle
@app.route('/admin/duyuru-ekle', methods=['GET', 'POST'])
def announcement_add():
    if 'admin_id' not in session:
        flash('Bu sayfaya erişmek için önce admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    admin = Admin.query.get(session.get('admin_id'))
    if not admin:
        flash('Admin hesabı bulunamadı, lütfen tekrar giriş yapınız.', 'danger')
        session.pop('admin_id', None)
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        baslik = request.form.get('baslik', '').strip()
        icerik = request.form.get('icerik', '').strip()
        hedef_kitle = request.form.get('hedef_kitle')

        if not baslik or not icerik or not hedef_kitle:
            flash('Lütfen tüm alanları eksiksiz doldurun.', 'danger')
            return redirect(url_for('announcement_add'))

        yeni_duyuru = Announcement(
            title=baslik,
            content=icerik,
            target_group=hedef_kitle
        )
        db.session.add(yeni_duyuru)
        db.session.commit()

        flash('Duyuru başarıyla eklendi.', 'success')
        return redirect(url_for('announcement_add'))

    announcements = Announcement.query.order_by(Announcement.date_created.desc()).all()

    return render_template('admin_duyuru_ekle.html', admin=admin, announcements=announcements)



# Duyuru Düzenle
@app.route('/admin/duyuru-duzenle/<int:id>', methods=['GET', 'POST'])
def announcement_edit(id):
    if 'admin_id' not in session:
        flash('Lütfen önce admin girişi yapın.', 'danger')
        return redirect(url_for('admin_login'))

    duyuru = Announcement.query.get_or_404(id)

    if request.method == 'POST':
        duyuru.title = request.form.get('baslik', '').strip()
        duyuru.content = request.form.get('icerik', '').strip()
        duyuru.target_group = request.form.get('hedef_kitle')

        if not duyuru.title or not duyuru.content or not duyuru.target_group:
            flash('Lütfen tüm alanları doldurun.', 'danger')
            return redirect(url_for('announcement_edit', id=id))

        db.session.commit()
        flash('Duyuru başarıyla güncellendi.', 'success')
        return redirect(url_for('announcement_add'))

    return render_template('admin_duyuru_duzenle.html', duyuru=duyuru)


# Duyuru Sil
@app.route('/admin/duyuru-sil/<int:id>', methods=['POST'])
def announcement_delete(id):
    if 'admin_id' not in session:
        flash('Lütfen önce admin girişi yapın.', 'danger')
        return redirect(url_for('admin_login'))

    duyuru = Announcement.query.get_or_404(id)
    db.session.delete(duyuru)
    db.session.commit()

    flash('Duyuru başarıyla silindi.', 'success')
    return redirect(url_for('announcement_add'))



@app.route('/admin/technician/edit/<int:id>', methods=['GET', 'POST'])
def edit_technician(id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    technician = Technician.query.get_or_404(id)

    if request.method == 'POST':
        technician.ad = request.form['ad']
        technician.soyad = request.form['soyad']
        technician.email = request.form['email']
        technician.telefon = request.form.get('telefon')
        technician.uzmanlik = request.form['uzmanlik']
        technician.adres = request.form.get('adres')
        technician.aciklama = request.form.get('aciklama')

        # Checkboxlar gönderilmezse form'da olmuyor, o yüzden kontrol et
        technician.onay = 'onay' in request.form
        technician.iptal = 'iptal' in request.form

        db.session.commit()
        flash('Tekniker bilgileri güncellendi.', 'success')
        return redirect(url_for('manage_technicians'))  # Veya istediğin başka sayfa

    return render_template('edit_technician.html', technician=technician)


@app.route('/admin/technician/delete/<int:id>', methods=['POST'])
def delete_technician(id):
    if 'admin_id' not in session:
        flash('Admin girişi yapmalısınız!', 'danger')
        return redirect(url_for('admin_login'))

    technician = Technician.query.get_or_404(id)
    db.session.delete(technician)
    db.session.commit()

    flash(f'{technician.ad} {technician.soyad} isimli tekniker silindi.', 'success')
    return redirect(url_for('manage_technicians'))


#if __name__ == '__main__':
 #   with app.app_context():
  #      db.create_all()
   # app.run(debug=True)

import os
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
