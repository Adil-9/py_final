from flask import Flask, render_template, url_for, request, flash, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime



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
    shirts = db.Column(db.Integer)
    hoodies = db.Column(db.Integer)

@app.route('/')
def main():
    logout_user()
    return render_template('main.html')


@app.route('/sign-up', methods=['GET', 'POST'])
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
            new_user = User(email=email, username=username, password=generate_password_hash(password1, method='sha256'), shirts=0, hoodies=0)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            return redirect(url_for('home'))
            #add user to database
    return render_template('sign-up.html')


with app.app_context():
    db.create_all()


@app.route('/products', methods=['GET', 'POST'])
def products():
    if request.method == 'POST':
        user = current_user
        shirts = request.form.get('quantity_shirts')
        hoodies = request.form.get('quantity_hoodies')
        db.session.delete(user)
        user.shirts = shirts
        user.hoodies = hoodies
        db.session.add(user)
        db.session.commit()
    cur_date = datetime.datetime.now()
    min_date = cur_date + datetime.timedelta(days=1)
    apr_date = cur_date + datetime.timedelta(days=3)
    to_pass = 'minimum shipping date ' + str(min_date.replace(microsecond=0)) + ' | maximum shipping date ' + str(apr_date.replace(microsecond=0))
    return render_template('products.html', date_time=to_pass)


@app.route('/login', methods=['GET', 'POST'])
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


@app.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    if request.method == 'POST':
        p1 = request.form.get('password1')
        p2 = request.form.get('password2')
        person = current_user
        if p2 != p1:
            flash('Passwords are not the same, try again.', category='error')
        elif check_password_hash(person.password, p1):
            db.session.delete(person)
            db.session.commit()
            logout()
            return render_template('main.html')
        else:
            flash("Password is incorrect!")
    return render_template('delete.html')


@app.route('/personal', methods=['GET', 'POST'])
@login_required
def personal():
    if request.method == 'POST':
        p1 = request.form.get('password1')
        p2 = request.form.get('password2')
        p3 = request.form.get('password3')
        person = current_user
        if len(p2) < 8 or len(p3) < 8:
            flash('Passwords too short, try again.', category='error')
        elif p2 != p3:
            flash('Passwords are not the same, try again.', category='error')
        elif check_password_hash(person.password, p1):
            hashed_pass = generate_password_hash(p2, method='sha256')
            db.session.delete(person)
            person.password = hashed_pass
            db.session.add(person)
            db.session.commit()
    return render_template('personal.html')


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
    return render_template('main.html')


@app.route('/about')
def about():
    return render_template('about.html')


login_manager = LoginManager()
login_manager.login_view = '/login' #where user is directed if not logged in
login_manager.init_app(app) #telling it which app were using


@app.route('/cart', methods=['GET', 'POST'])
@login_required
def cart():
    if request.method == 'POST':
        user = current_user
        db.session.delete(user)
        user.shirts = 0
        user.hoodies = 0
        db.session.add(user)
        db.session.commit()
    data_shirts = str(current_user.shirts) + ' Total Price ' + str(round(current_user.shirts*17.99, 2)) + '$'
    data_hoodies = str(current_user.hoodies) + ' Total Price ' + str(round(current_user.hoodies*17.99, 2)) + '$'
    if current_user.shirts == 69 and current_user.hoodies == 420:
        return render_template('cart.html', data_hoodies=data_hoodies, data_shirts=data_shirts, secret="PASHALKA")
    return render_template('cart.html', data_hoodies=data_hoodies, data_shirts=data_shirts)


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))  # looking for primary key of user


if __name__ == "__main__":
    app.run(debug=True)

