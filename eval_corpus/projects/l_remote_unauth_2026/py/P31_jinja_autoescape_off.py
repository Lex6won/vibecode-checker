from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader("templates"), autoescape=False)

def render(name, comment):
    return env.get_template("page.html").render(name=name, comment=comment)
