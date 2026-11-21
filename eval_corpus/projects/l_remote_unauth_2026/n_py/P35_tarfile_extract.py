import tarfile

def unpack(archive_path: str):
    with tarfile.open(archive_path) as tar:
        tar.extractall("/srv/app/models", filter="data")
