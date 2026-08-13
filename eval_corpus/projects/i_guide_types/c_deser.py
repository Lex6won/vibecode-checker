import pickle, yaml
from flask import request

def load_state():
    return pickle.loads(request.data)

def load_cfg():
    return yaml.load(request.data, Loader=yaml.Loader)
