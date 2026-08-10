import os, subprocess
from flask import request

def convert():
    name = request.args["file"]
    os.system("convert /data/" + name + " /out/a.png")
    subprocess.call(f"hwp5txt {name}", shell=True)
