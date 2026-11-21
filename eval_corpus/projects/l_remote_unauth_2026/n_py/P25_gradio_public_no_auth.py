import os
import gradio as gr

def answer(question):
    return run_internal_search(question)

demo = gr.Interface(fn=answer, inputs="text", outputs="text")
demo.launch(server_name="127.0.0.1", auth=(os.environ["UI_USER"], os.environ["UI_PASSWORD"]))
