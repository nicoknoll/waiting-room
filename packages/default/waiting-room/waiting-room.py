import os


def main(event, context):
    return {"body": dict(os.environ)}
