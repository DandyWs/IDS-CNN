from website import create_app, db
from website.models import User

app = create_app()
with app.app_context():
    users = User.query.all()
    for user in users:
        print(user.id, user.username, user.email, user.profile_pic)