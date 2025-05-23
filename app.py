import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from forms import LoginForm, SignupForm, PasswordResetRequestForm, PasswordResetForm

# Flask Uygulaması
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-123')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Dosya yükleme klasörünü oluştur
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Veritabanı ve Migrasyon
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

# Modeller
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)
    social_id = db.Column(db.String(100), unique=True, nullable=True)
    social_provider = db.Column(db.String(50), nullable=True)
    
    # İlişkiler
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy=True)
    sent_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.from_user_id', backref='from_user', lazy=True)
    received_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.to_user_id', backref='to_user', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    image_path = db.Column(db.String(120))
    notes = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(16), default='pending')  # pending, accepted, rejected
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Yardımcı Fonksiyonlar
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Route'lar
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Başarıyla giriş yapıldı!', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Kullanıcı adı veya şifre hatalı', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter((User.username == form.username.data) | 
                                      (User.email == form.email.data)).first()
        if existing_user:
            flash('Bu kullanıcı adı veya email zaten kullanımda', 'danger')
        else:
            user = User(
                username=form.username.data,
                email=form.email.data
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Hesabınız başarıyla oluşturuldu!', 'success')
            return redirect(url_for('chat'))
    
    return render_template('signup.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Başarıyla çıkış yapıldı', 'info')
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))
    
    # Arkadaşlık istekleri
    incoming = FriendRequest.query.filter_by(to_user_id=user.id, status='pending').all()
    outgoing = FriendRequest.query.filter_by(from_user_id=user.id, status='pending').all()

    # Arkadaş listesi
    # Arkadaş listesi sorgusu (tam düzeltilmiş hali)
friends = db.session.query(User).join(
    FriendRequest,
    db.or_(
        db.and_(
            FriendRequest.from_user_id == user.id,
            FriendRequest.to_user_id == User.id,
            FriendRequest.status == 'accepted'
        ),
        db.and_(
            FriendRequest.to_user_id == user.id,
            FriendRequest.from_user_id == User.id,
            FriendRequest.status == 'accepted'
        )
    )
).all()
    # Mesajlar
    messages = Message.query.filter(
        (Message.sender_id == user.id) | (Message.recipient_id == user.id)
    ).order_by(Message.timestamp.desc()).all()

    return render_template('chat.html',
                         user=user,
                         friends=friends,
                         messages=messages,
                         incoming_requests=incoming,
                         outgoing_requests=outgoing)

@app.route('/add_friend', methods=['POST'])
def add_friend():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = request.form.get('friend_username')
    user = User.query.get(session['user_id'])
    friend = User.query.filter_by(username=username).first()
    
    if not friend:
        flash('Kullanıcı bulunamadı', 'danger')
    elif friend.id == user.id:
        flash('Kendinize istek gönderemezsiniz', 'warning')
    else:
        # Daha önce istek gönderilmiş mi kontrol et
        existing_request = FriendRequest.query.filter(
            ((FriendRequest.from_user_id == user.id) & (FriendRequest.to_user_id == friend.id) |
            ((FriendRequest.from_user_id == friend.id) & (FriendRequest.to_user_id == user.id))
        ).first()
        
        if existing_request:
            flash('Zaten bir istek gönderildi', 'info')
        else:
            new_request = FriendRequest(
                from_user_id=user.id,
                to_user_id=friend.id
            )
            db.session.add(new_request)
            db.session.commit()
            flash('Arkadaşlık isteği gönderildi', 'success')
    
    return redirect(url_for('chat'))

@app.route('/handle_request', methods=['POST'])
def handle_friend_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    request_id = request.form.get('request_id')
    action = request.form.get('action')
    user_id = session['user_id']
    
    friend_request = FriendRequest.query.get(request_id)
    if not friend_request or friend_request.to_user_id != user_id:
        flash('Geçersiz istek', 'danger')
        return redirect(url_for('chat'))
    
    if action == 'accept':
        friend_request.status = 'accepted'
        # Karşılıklı arkadaşlık oluştur
        db.session.commit()
        flash('Arkadaşlık isteği kabul edildi', 'success')
    elif action == 'reject':
        friend_request.status = 'rejected'
        db.session.commit()
        flash('Arkadaşlık isteği reddedildi', 'info')
    
    return redirect(url_for('chat'))

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    recipient_id = request.form.get('recipient_id')
    notes = request.form.get('notes')
    file = request.files.get('image')
    
    if not recipient_id:
        flash('Alıcı seçmelisiniz', 'danger')
        return redirect(url_for('chat'))
    
    if not file or not allowed_file(file.filename):
        flash('Geçerli bir resim dosyası seçmelisiniz', 'danger')
        return redirect(url_for('chat'))
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    message = Message(
        sender_id=user.id,
        recipient_id=recipient_id,
        image_path=filepath,
        notes=notes
    )
    db.session.add(message)
    db.session.commit()
    
    flash('Mesajınız gönderildi', 'success')
    return redirect(url_for('chat'))

# Başlangıç Komutu
@app.cli.command('initdb')
def initdb_command():
    """Veritabanını temizler ve yeniden oluşturur"""
    db.drop_all()
    db.create_all()
    print('Veritabanı başarıyla oluşturuldu')

if __name__ == '__main__':
    app.run(debug=True)
