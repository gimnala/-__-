import os
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    groupbuy_id = db.Column(db.Integer, db.ForeignKey('groupbuy.id'), primary_key=True)

class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    notice_id = db.Column(db.Integer, db.ForeignKey('notice.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Routes
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

@app.route('/book/<int:book_id>')
@login_required
def book_detail(book_id):
    book = Book.query.get_or_404(book_id)
    groupbuy = GroupBuy.query.filter_by(book_id=book_id).first()
    participants = []
    joined = False
    if groupbuy:
        joined = GroupBuyParticipant.query.filter_by(user_id=current_user.id, groupbuy_id=groupbuy.id).first() is not None
        for p in GroupBuyParticipant.query.filter_by(groupbuy_id=groupbuy.id):
            user = User.query.get(p.user_id)
            if user:
                participants.append(user.username)
    creator_user = User.query.get(book.creator_id) if book.creator_id else None
    return render_template('book_detail.html', book=book, groupbuy=groupbuy, joined=joined, participants=participants, creator_user=creator_user)

@app.route('/groupbuy/start/<int:book_id>', methods=['POST'])
@login_required
def start_groupbuy(book_id):
    start = datetime.datetime.now()
    end = start + datetime.timedelta(days=7)
    groupbuy = GroupBuy(book_id=book_id, starter_id=current_user.id, start_date=start, end_date=end)
    db.session.add(groupbuy)
    db.session.commit()
    return redirect(f'/book/{book_id}')

@app.route('/groupbuy/join/<int:groupbuy_id>', methods=['POST'])
@login_required
def join_groupbuy(groupbuy_id):
    if not GroupBuyParticipant.query.filter_by(user_id=current_user.id, groupbuy_id=groupbuy_id).first():
        db.session.add(GroupBuyParticipant(user_id=current_user.id, groupbuy_id=groupbuy_id))
        db.session.commit()
    gb = GroupBuy.query.get(groupbuy_id)
    return redirect(f'/book/{gb.book_id}')

@app.route('/groupbuy/cancel/<int:groupbuy_id>', methods=['POST'])
@login_required
def cancel_groupbuy(groupbuy_id):
    gb = GroupBuy.query.get_or_404(groupbuy_id)
    if gb.starter_id != current_user.id:
        abort(403)
    db.session.delete(gb)
    db.session.commit()
    return redirect(f'/book/{gb.book_id}')

@app.route('/cancel_participation/<int:groupbuy_id>', methods=['GET'])
@login_required
def cancel_participation(groupbuy_id):
    participation = GroupBuyParticipant.query.filter_by(groupbuy_id=groupbuy_id, user_id=current_user.id).first()
    if participation:
        db.session.delete(participation)
        db.session.commit()
        flash('공동구매 참여가 취소되었습니다.')
    else:
        flash('취소할 수 있는 참여 정보가 없습니다.')
    return redirect('/mypage')

@app.route('/book/delete/<int:book_id>', methods=['POST'])
@login_required
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    if book.creator_id != current_user.id:
        abort(403)
    db.session.delete(book)
    db.session.commit()
    return redirect('/search')

@app.route('/notice', methods=['GET', 'POST'])
@login_required
def notice():
    if request.method == 'POST':
        n = Notice(title=request.form['title'], content=request.form['content'], author_id=current_user.id)
        db.session.add(n)
        db.session.commit()
        return redirect('/notice')
    notices = Notice.query.all()
    return render_template('notice.html', notices=notices)

@app.route('/notice/<int:notice_id>', methods=['GET', 'POST'])
@login_required
def notice_detail(notice_id):
    notice = Notice.query.get_or_404(notice_id)
    if request.method == 'POST':
        comment = Comment(content=request.form['content'], notice_id=notice_id, author_id=current_user.id)
        db.session.add(comment)
        db.session.commit()
    comments = Comment.query.filter_by(notice_id=notice_id).all()
    return render_template('notice_detail.html', notice=notice, comments=comments)

@app.route('/notice/delete/<int:notice_id>', methods=['POST'])
@login_required
def delete_notice(notice_id):
    n = Notice.query.get_or_404(notice_id)
    if n.author_id != current_user.id:
        abort(403)
    db.session.delete(n)
    db.session.commit()
    return redirect('/notice')

@app.route('/comment/delete/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    c = Comment.query.get_or_404(comment_id)
    nid = c.notice_id
    if c.author_id != current_user.id:
        abort(403)
    db.session.delete(c)
    db.session.commit()
    return redirect(f'/notice/{nid}')

@app.route('/mypage')
@login_required
def mypage():
    mybooks = Book.query.filter_by(creator_id=current_user.id).all()
    mygroupbuys = GroupBuyParticipant.query.filter_by(user_id=current_user.id).all()
    gb_ids = [g.groupbuy_id for g in mygroupbuys]
    joined_books = GroupBuy.query.filter(GroupBuy.id.in_(gb_ids)).all()
    return render_template('mypage.html', books=mybooks, joined_ids=gb_ids, joined_books=joined_books)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
