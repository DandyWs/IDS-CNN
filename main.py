from website import create_app
from flask import Flask
from flask_migrate import Migrate
# from website import database  # Import the database object

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)  # Set debug=True for development; change to False in production