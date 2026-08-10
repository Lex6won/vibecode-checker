from flask import request, render_template_string

def page():
    tpl = "<h1>" + request.args["name"] + "</h1>"
    return render_template_string(tpl)
