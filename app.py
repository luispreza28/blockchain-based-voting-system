from website import create_app
from flask_migrate import Migrate
from website import db
from flask_login import LoginManager
from website import models

app = create_app()
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))


if __name__ == '__main__':
    app.run(debug=True)
