import firebase
from .config import *

app = firebase.initialize_app(config)

auth = app.auth()
database = app.database()
