from flask import Flask, redirect, render_template, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///feedback_db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['SECRET_KEY'] = 'sadas32e2'
debug = DebugToolbarExtension(app)

connect_db(app)


@app.route('/')
def home_page():
    '''Redirects to the root route'''
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    '''Shows the register form'''
    form = RegisterForm()

    if form.validate_on_submit():

        user = User.register(
            username=form.username.data,
            password=form.password.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data
        )

        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError as error:
            if 'username' in str(error):
                flash('Username taken, please try again', 'danger')
                return render_template('register.html', form=form)
            if 'email' in str(error):
                flash('Email taken, please try again', 'danger')
                return render_template('register.html', form=form)

        flash('Account created!', 'success')
        session['user'] = user.username

        return redirect(f'/users/{user.username}')
    else:
        return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Add authentication to the form and shows the login form'''
    
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password=form.password.data

        user = User.authenticate(username=username, password=password)

        if user:
            flash(f'Welcome back, {user.first_name}!', 'success')
            session['user'] = user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors = ['Invalid username or password. Please try again']
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    '''Logs out user and clears session'''

    session.pop('user')
    flash('See you soon!', 'danger')
    return redirect('/')


@app.route('/users/<username>')
def show_user_info(username):
    '''Shows the information about the user if the user is logged in'''

    if 'user' not in session:
        flash('Please log in first', 'danger')
        return redirect('/login')
    else:
        user = User.query.filter_by(username=username).first()
        if user.username == session['user']:
            feedbacks = Feedback.query.filter_by(username=user.username).all()
            return render_template('user.html', user=user, feedbacks=feedbacks)
        else:
            flash('You do not have permission', 'danger')
            return redirect('/login')
    
@app.route('/users/<username>/delete')
def delete_user(username):
    '''Deletes user from db'''

    if 'user' not in session:
        flash('Please log in first', 'danger')
        return redirect('/login')
    else:
        user = User.query.filter_by(username=username).first()
        feedbacks = Feedback.query.filter_by(username=username).all()
        if user.username == session['user']:

            session.pop('user')
            db.session.delete(user)
            for feedback in feedbacks:
                db.session.delete(feedback)
            db.session.commit()

            flash('Sorry to see you go!', 'warning')
            return redirect('/')
        else:
            flash('You do not have permission', 'danger')
            return redirect('/login')

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    '''Shows form to add feedback'''

    form = FeedbackForm()

    if 'user' not in session:
        flash('Please log in first', 'danger')
        return redirect('/login')
    else:
        user = User.query.filter_by(username=username).first()
        if user.username == session['user']:
            if form.validate_on_submit():
                title = form.title.data
                content = form.content.data

                feedback = Feedback(title=title, content=content, username=user.username)
                db.session.add(feedback)
                db.session.commit()
                flash('Thank you for your feedback', 'success')
                return redirect(f'/users/{user.username}')
            else:
                return render_template('feedback.html', form=form)
        else:
            flash('You do not have permission', 'danger')
            return redirect('/login')
        
@app.route('/feedback/<int:id>/update', methods=['GET', 'POST'])
def edit_feedback(id):
    '''Shows form to edit feedback'''
    form = FeedbackForm()

    if 'user' not in session:
        flash('Please log in first', 'danger')
        return redirect('/login')
    else:
        feedback = Feedback.query.get_or_404(id)
        user = feedback.username
        if user == session['user']:
            if form.validate_on_submit():
                title = form.title.data
                content = form.content.data

                feedback.title = title
                feedback.content = content

                db.session.add(feedback)
                db.session.commit()

                flash('Feedback edited', 'success')
                return redirect(f'/users/{user}')
            else:
                return render_template('update_feedback.html', form=form, user=user)
        else:
            flash('You do not have permission', 'danger')
            return redirect('/login')

@app.route('/feedback/<int:id>/delete')
def delete_feedback(id):
    '''Deletes feedback from db'''

    if 'user' not in session:
        flash('Please log in first', 'danger')
        return redirect('/login')
    else:
        feedback = Feedback.query.get_or_404(id)
        user = feedback.username
        if user == session['user']:

            db.session.delete(feedback)
            db.session.commit()
            return redirect(f'/users/{user}')
        else:
            flash('You do not have permission', 'danger')
            return redirect('/login')