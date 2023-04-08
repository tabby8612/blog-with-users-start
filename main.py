from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    g,
    session,
    abort,
)
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    current_user,
    logout_user,
)
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps


app = Flask(__name__)
app.config["SECRET_KEY"] = "8BYkEfBA6O6donzWlSihBXox7C0sKR6b"
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.app_context().push()
db = SQLAlchemy(app)


##CONFIGURE TABLES


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    comment_author = relationship("User", back_populates="comments")

    text = db.Column(db.String(250), nullable=False)


db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return (
                "<h1>Forbidden Error</h1></br><p>The page you are trying to access is not accessible</p>",
                403,
            )
        return f(*args, **kwargs)

    return decorated_function


is_logged_in = False
is_admin = False


@app.route("/")
def get_all_posts():
    posts = BlogPost.query.all()
    print(posts)
    return render_template(
        "index.html", all_posts=posts, is_login=is_logged_in, is_user_admin=is_admin
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        new_email = request.form["email"]
        passw = request.form["password"]

        secure_password = generate_password_hash(
            password=passw, method="pbkdf2:sha256", salt_length=8
        )

        new_name = request.form["name"]
        user = User(email=new_email, password=secure_password, name=new_name)

        emails = [user.email for user in User.query.all()]

        if new_email not in emails:
            db.session.add(user)
            db.session.commit()

            return redirect(url_for("get_all_posts"))
        else:
            flash("You are already registered in our system. Please login")
            return redirect(url_for("login"))

    form = RegisterForm()
    return render_template("register.html", form=form, is_login=False)


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        entered_email = request.form.get("email")
        entered_password = request.form.get("password")

        users = User.query.all()
        emails = [user.email for user in users]

        for user in users:
            if (
                user.email == entered_email
                and check_password_hash(pwhash=user.password, password=entered_password)
                == True
            ):
                if user.id == 1:
                    global is_admin
                    is_admin = True
                    g.id = 1

                user = User.query.filter_by(email=entered_email).first()
                login_user(user)
                global is_logged_in
                is_logged_in = current_user.is_authenticated
                return redirect(url_for("get_all_posts"))

        if entered_email in emails:
            flash("Password is incorrect. Please Try again")
            return redirect(url_for("login"))

    form = LoginForm()
    return render_template("login.html", form=form, is_login=False)


@app.route("/logout")
def logout():
    global is_logged_in, is_admin
    is_logged_in = False
    is_admin = False
    return redirect(url_for("get_all_posts"))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=request.form.get("text"),
            comment_author=current_user,
            parent_post=requested_post,
        )
        db.session.add(new_comment)
        db.session.commit()
        return render_template("post.html", post=requested_post, form=comment_form)

    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    if is_admin == False:
        return abort(403)

    form = CreatePostForm()

    if request.method == "POST":
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author_id=current_user.id,
                date=date.today().strftime("%B %d, %Y"),
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))

    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
def edit_post(post_id):
    if is_admin == False:
        return abort(403)

    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body,
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    if is_admin == False:
        return abort(403)

    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
