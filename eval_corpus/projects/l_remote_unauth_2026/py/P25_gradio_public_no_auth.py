import gradio as gr

def answer(question):
    return run_internal_search(question)

demo = gr.Interface(fn=answer, inputs="text", outputs="text")
demo.launch(server_name="0.0.0.0", share=True)
