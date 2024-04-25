from flask import jsonify, abort, render_template, request

from . import app
#from data.tasklist import tasks_list
from .models import User
#from .models import Task
#from .auth import basic_auth, token_auth

@app.route('/')
def index():
    return render_template('index.html')
