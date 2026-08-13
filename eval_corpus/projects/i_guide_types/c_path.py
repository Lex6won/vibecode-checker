from flask import request, send_file

def download():
    fn = request.args["name"]
    return send_file("/data/upload/" + fn)

def read():
    p = request.args["p"]
    return open("/var/app/" + p).read()
