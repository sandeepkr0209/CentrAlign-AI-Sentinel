"""Tiny sample web service used as SENTINEL's sandbox repository."""
from flask import Flask, jsonify

from utils import load_config

app = Flask(__name__)
CONFIG = load_config("config.yaml")


@app.route("/health")
def health():
    return jsonify(status="ok", name=CONFIG.get("name", "sample"))


if __name__ == "__main__":
    app.run()
