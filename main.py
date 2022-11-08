from flask import Flask, render_template, url_for, request, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from os import path



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'very secret key'
db = SQLAlchemy(app)
db.init_app(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    username = db.Column(db.String(150))



@app.route('/')
def main():
    logout_user()
    return render_template('main.html')


@app.route('/sign-up', methods=['GET','POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('The length of an email must be greater than 4 characters', category='error')
        elif len(username) < 2:
            flash("The length of a username must be greater than 2 characters", category='error')
        elif password1 != password2:
            flash("Passwords don't match!", category='error')
        elif len(password1) < 7:
            flash("The length of the password must be greater than 7 characters", category='error')
        else:
            new_user = User(email=email, username=username, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)

            return redirect(url_for('home'))
            #add user to database

    with app.app_context():
        db.create_all()


    return render_template('sign-up.html')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()  # ищет нужную запись из базы данных
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                return redirect(url_for('home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template('login.html')


@app.route('/home')
@login_required
def home():
    return render_template('home.html')


@app.route('/main')
def main_pg():
    return render_template('main.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('/'))


@app.route('/products')
def products():
    return render_template('products.html')


@app.route('/about')
def about():
    return render_template('about.html')

login_manager = LoginManager()
login_manager.login_view = '/login' #where user is directed if not logged in
login_manager.init_app(app) #telling it which app were using


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))  # looking for primary key of user


if __name__ == "__main__":
    app.run(debug=True)

