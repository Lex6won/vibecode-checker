import tarfile

def unpack(uploaded_path: str):
    with tarfile.open(uploaded_path) as tar:
        tar.extractall("/srv/app/models")
