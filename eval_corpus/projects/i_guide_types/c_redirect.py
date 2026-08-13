from flask import request, redirect

def go():
    return redirect(request.args["next"])
