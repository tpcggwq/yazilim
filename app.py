   from config import Config
   app.config.from_object(Config)
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import click
from forms import LoginForm, SignupForm, PasswordResetRequestForm, PasswordResetForm
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash, check_password_hash
import os
from authlib.integrations.flask_client import OAuth
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.secret_key = os.environ.get('SECRET_KEY', '_5#y2LF4Q8z]/')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True

# Initialize CSRF protection
csrf = CSRFProtect(app)

# OAuth configuration
oauth = OAuth(app)

# Google OAuth configuration
# 1. Go to https://console.cloud.google.com/
# 2. Create a new project or select existing one
# 3. Go to APIs & Services > OAuth consent screen
# 4. Configure the consent screen (External)
# 5. Go to APIs & Services > Credentials
# 6. Create OAuth 2.0 Client ID
# 7. Copy the Client ID and Client Secret below
google = oauth.register(
    name='google',
    client_id='62020230472-vlh4e8cs27s9t50odpvvud24h4r5d6vq.apps.googleusercontent.com',  # Sizin Client ID'niz
    client_secret='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',  # Sizin Client Secret'ınız
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Flask-Mail ayarları
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'cagingiraytoprak@gmail.com'
app.config['MAIL_PASSWORD'] = 'wean cjts nour efei'
app.config['MAIL_DEFAULT_SENDER'] = 'cagingiraytoprak@gmail.com'

mail = Mail(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)  # Made nullable for social login
    social_id = db.Column(db.String(100), unique=True, nullable=True)
    social_provider = db.Column(db.String(50), nullable=True)

    def __init__(self, username, email, password=None, social_id=None, social_provider=None):
        self.username = username
        self.email = email
        self.password = password
        self.social_id = social_id
        self.social_provider = social_provider

# Kullanıcı giriş/kayıt log modeli
class UserLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(32), nullable=False)
    event = db.Column(db.String(16), nullable=False)  # 'login' veya 'signup'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create command to initialize database
@click.command(name="create_tables")
@with_appcontext
def create_tables():
    db.create_all()

app.cli.add_command(create_tables)

# home page route for after login
@app.route('/home')
def home():
    if 'email' not in session:
        flash("You are not logged in. Please login first.", "danger")
        return redirect(url_for('login'))
    return "This is your home page!"

@app.route('/chat')
def chat():
    if 'email' not in session:
        flash("Giriş yapmalısınız.", "danger")
        return redirect(url_for('login'))
    user = User.query.filter_by(email=session['email']).first()
    # Kullanıcının arkadaşları (sadece kabul edilenler)
    friends = User.query.join(Friendship, Friendship.friend_id == User.id).filter(Friendship.user_id == user.id).all()
    # Kullanıcıya gelen ve gönderilen mesajlar
    messages = MessageModel.query.filter((MessageModel.sender_id == user.id) | (MessageModel.recipient_id == user.id)).all()
    # Gelen arkadaşlık istekleri
    incoming_requests = FriendRequest.query.filter_by(to_user_id=user.id, status='pending').all()
    # Giden arkadaşlık istekleri
    outgoing_requests = FriendRequest.query.filter_by(from_user_id=user.id, status='pending').all()
    return render_template('chat.html', user=user, friends=friends, messages=messages, incoming_requests=incoming_requests, outgoing_requests=outgoing_requests)

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    signup_form = SignupForm()
    
    if login_form.validate_on_submit():
        username = login_form.username.data
        password = login_form.password.data

        try:
            user = User.query.filter_by(username=username).first()
            if user is None:
                flash("Böyle bir kullanıcı adı yok. Lütfen kayıt olun.", "danger")
            else:
                if user.password and check_password_hash(user.password, password):
                    session.clear()
                    session['email'] = user.email
                    session['username'] = user.username
                    # Giriş logu ekle
                    db.session.add(UserLog(user_id=user.id, username=user.username, event='login'))
                    db.session.commit()
                    flash(f"Hoş geldin, {user.username}. Giriş yapıldı.", "success")
                    return redirect(url_for('chat'))
                else:
                    flash("Şifre yanlış!", "danger")
        except Exception as e:
            flash("Giriş sırasında bir hata oluştu. Lütfen tekrar deneyin.", "danger")
            app.logger.error(f"Login error: {str(e)}")

    if signup_form.validate_on_submit():
        username = signup_form.username.data
        email = signup_form.email.data
        password = signup_form.password.data

        try:
            existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
            if existing_user:
                flash("Bu kullanıcı adı veya e-posta zaten kullanılıyor.", "danger")
            else:
                password = generate_password_hash(password)
                new_user = User(username=username, email=email, password=password)
                db.session.add(new_user)
                db.session.commit()
                session.clear()
                session['email'] = email
                session['username'] = username
                # Kayıt logu ekle
                db.session.add(UserLog(user_id=new_user.id, username=new_user.username, event='signup'))
                db.session.commit()
                flash("Kayıt başarılı, otomatik giriş yapıldı.", "success")
                return redirect(url_for('chat'))
        except Exception as e:
            db.session.rollback()
            flash("Kayıt sırasında bir hata oluştu. Lütfen tekrar deneyin.", "danger")
            app.logger.error(f"Signup error: {str(e)}")

    return render_template("login.html", form=login_form, signup_form=signup_form)

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri, state=session.get('_csrf_token'))

@app.route('/login/google/authorize')
def google_authorize():
    print("Google authorize route başladı")
    try:
        token = google.authorize_access_token()
        print("Token alındı:", token)
        # Nonce parametresi ekle
        nonce = token.get('userinfo', {}).get('nonce')
        userinfo = google.parse_id_token(token, nonce=nonce)
        print("Kullanıcı bilgisi:", userinfo)
        
        email = userinfo.get('email')
        social_id = userinfo.get('sub')
        print("Email:", email, "Social ID:", social_id)
        user = User.query.filter_by(social_id=social_id, social_provider='google').first()
        if not user:
            user = User.query.filter_by(email=email).first()
            if user:
                user.social_id = social_id
                user.social_provider = 'google'
                db.session.commit()
                print("Mevcut kullanıcıya social_id ve provider eklendi")
            else:
                username = email.split('@')[0]
                base_username = username
                i = 1
                while User.query.filter_by(username=username).first():
                    username = f"{base_username}{i}"
                    i += 1
                user = User(username=username, email=email, social_id=social_id, social_provider='google')
                db.session.add(user)
                db.session.commit()
                print("Yeni kullanıcı oluşturuldu:", username)
        session['email'] = email
        session['username'] = user.username
        print("Session ayarlandı:", session)
        flash(f"Welcome, {user.username}. You are logged in with Google.", "success")
        print("Google authorize route SONU")
        return redirect(url_for('chat'))
    except Exception as e:
        print("Google login hatası:", str(e))
        flash(f"Google login hatası: {str(e)}", "danger")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return email

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = generate_reset_token(user.email)
            reset_url = url_for('reset_password', token=token, _external=True)
            # E-posta gönder
            try:
                msg = Message('Şifre Sıfırlama', recipients=[user.email])
                msg.body = f'Selam,\n\nŞifreni sıfırlamak için aşağıdaki bağlantıya tıkla:\n{reset_url}\n\nEğer bu isteği sen yapmadıysan bu e-postayı dikkate alma.'
                mail.send(msg)
                flash('Şifre sıfırlama bağlantısı e-posta adresine gönderildi.', 'info')
            except Exception as e:
                app.logger.error(f'E-posta gönderilemedi: {str(e)}')
                flash(f'E-posta gönderilemedi: {str(e)}', 'danger')
        else:
            flash('Bu e-posta ile kayıtlı bir kullanıcı bulunamadı.', 'danger')
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash("Geçersiz veya süresi dolmuş bağlantı.", "danger")
        return redirect(url_for('login'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(form.password.data)
            db.session.commit()
            flash("Şifreniz başarıyla güncellendi. Giriş yapabilirsiniz.", "success")
            return redirect(url_for('login'))
        else:
            flash("Kullanıcı bulunamadı.", "danger")
    return render_template('reset_password.html', form=form)

# Arkadaşlık modeli
class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Mesaj modeli
class MessageModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_path = db.Column(db.String(120), nullable=False)
    notes = db.Column(db.Text, nullable=True)

# Arkadaşlık isteği modeli
class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(16), default='pending')  # 'pending', 'accepted', 'rejected'

# Arkadaş ekleme ve mesajlaşma route'ları
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@csrf.exempt
@app.route('/add_friend', methods=['POST'])
def add_friend():
    if 'username' not in session:
        return redirect(url_for('login'))
    friend_username = request.form.get('friend_username')
    user = User.query.filter_by(username=session['username']).first()
    friend = User.query.filter_by(username=friend_username).first()
    if not friend:
        flash('Kullanıcı bulunamadı.', 'danger')
    elif friend.id == user.id:
        flash('Kendinizi ekleyemezsiniz.', 'danger')
    else:
        existing_request = FriendRequest.query.filter_by(from_user_id=user.id, to_user_id=friend.id, status='pending').first()
        already_friends = Friendship.query.filter_by(user_id=user.id, friend_id=friend.id).first()
        if existing_request:
            flash('Zaten bu kullanıcıya istek gönderdiniz.', 'info')
        elif already_friends:
            flash('Bu kullanıcı zaten arkadaşınız.', 'info')
        else:
            db.session.add(FriendRequest(from_user_id=user.id, to_user_id=friend.id))
            db.session.commit()
            flash('Arkadaşlık isteği gönderildi.', 'success')
    return redirect(url_for('chat'))

@app.route('/friend_requests', methods=['POST'])
def handle_friend_request():
    if 'username' not in session:
        return redirect(url_for('login'))
    req_id = request.form.get('request_id')
    action = request.form.get('action')  # 'accept' veya 'reject'
    fr = FriendRequest.query.get(req_id)
    user = User.query.filter_by(username=session['username']).first()
    if fr and fr.to_user_id == user.id and fr.status == 'pending':
        if action == 'accept':
            # Arkadaşlığı iki yönlü ekle
            db.session.add(Friendship(user_id=fr.from_user_id, friend_id=fr.to_user_id))
            db.session.add(Friendship(user_id=fr.to_user_id, friend_id=fr.from_user_id))
            fr.status = 'accepted'
            db.session.commit()
            flash('Arkadaşlık isteği kabul edildi.', 'success')
        elif action == 'reject':
            fr.status = 'rejected'
            db.session.commit()
            flash('Arkadaşlık isteği reddedildi.', 'info')
    return redirect(url_for('chat'))

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'email' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(email=session['email']).first()
    recipient_id = int(request.form.get('recipient_id'))
    notes = request.form.get('notes')
    file = request.files.get('image')
    if file and file.filename:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        msg = MessageModel(sender_id=user.id, recipient_id=recipient_id, image_path=file_path, notes=notes)
        db.session.add(msg)
        db.session.commit()
        flash('Mesaj gönderildi.', 'success')
    else:
        flash('Fotoğraf seçmelisiniz.', 'danger')
    return redirect(url_for('chat'))

# Admin: Kayıtlı kullanıcıları listele
@app.route('/admin/users')
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

# Admin: Kullanıcı loglarını listele
@app.route('/admin/logs')
def admin_logs():
    logs = UserLog.query.order_by(UserLog.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)
