from flask import Flask
from flask_migrate import Migrate
from app import app, db  # Importe seu app e db do módulo principal

migrate = Migrate(app, db)

if __name__ == '__main__':
    app.run()