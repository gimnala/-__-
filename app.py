from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.secret_key = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    store = db.Column(db.String(100))
    link = db.Column(db.String(500))
    price = db.Column(db.Integer)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class GroupBuy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'))
    starter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    participants = db.relationship('User', secondary='groupbuy_participant')
    book = db.relationship('Book', backref='groupbuys')

class GroupBuyParticipant(db.Model):
    __tablename__ = 'groupbuy_participant'
    __table_args__ = {'extend_existing': True}
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    groupbuy_id = db.Column(db.Integer, db.ForeignKey('group_buy.id'), primary_key=True)

class Notice(db.Model):
    __tablename__ = 'notice'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    notice_id = db.Column(db.Integer, db.ForeignKey('notice.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash('이미 존재하는 사용자 이름입니다.')
            return redirect('/signup')
        hashed_pw = generate_password_hash(request.form['password'])
        user = User(username=request.form['username'], password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect('/')
        flash('로그인 실패')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/book/add', methods=['GET', 'POST'])
@login_required
def add_book():
    if request.method == 'POST':
        book = Book(title=request.form['title'], store=request.form['store'], link=request.form['link'],
                    price=int(request.form['price']), creator_id=current_user.id)
        db.session.add(book)
        db.session.commit()
        return redirect('/search')
    return render_template('add_book.html')

@app.route('/search')
def search():
    q = request.args.get('q', '')
    books = Book.query.filter(Book.title.contains(q)).all() if q else []
    return render_template('search_results.html', books=books)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
