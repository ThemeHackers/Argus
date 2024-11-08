from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

def create_app():
   
    app = Flask(__name__)

    app.config.from_pyfile(os.path.join(os.path.dirname(__file__), 'config/settings.py'))
 
    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

    return app

