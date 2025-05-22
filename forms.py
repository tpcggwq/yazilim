from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp

class LoginForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired()])
    password = PasswordField('Şifre', validators=[DataRequired()])
    submit = SubmitField('Giriş Yap')

class SignupForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired(), Length(min=3, max=20, message='Kullanıcı adı 3-20 karakter olmalı')])
    email = StringField('E-posta', validators=[
        DataRequired(),
        Email(message='Geçerli bir e-posta adresi girin')
    ])
    password = PasswordField('Şifre', validators=[
        DataRequired(),
        Length(min=3, max=10, message='Şifre 3-10 karakter olmalı'),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{3,10}$',
               message='Şifre en az bir harf ve bir rakam içermeli')
    ])
    confirm_password = PasswordField('Şifreyi Onayla', validators=[
        DataRequired(),
        EqualTo('password', message='Şifreler eşleşmiyor')
    ])
    submit = SubmitField('Kayıt Ol')

class PasswordResetRequestForm(FlaskForm):
    email = StringField('E-posta', validators=[DataRequired(), Email()])
    submit = SubmitField('Sıfırlama Bağlantısı Gönder')

class PasswordResetForm(FlaskForm):
    password = PasswordField('Yeni Şifre', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Yeni Şifre (Tekrar)', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Şifreyi Sıfırla')