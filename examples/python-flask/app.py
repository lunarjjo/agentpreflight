# Flask app configured for AgentPreflight-clean security posture.

import os

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)

    # Secrets come from the environment, never from source control.
    app.config["SECRET_KEY"] = os.environ["APP_SECRET_KEY"]
    # Debug mode is OFF by default and only raised in local shells.
    app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "0") == "1"

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


if __name__ == "__main__":
    # Local only, debug off; production uses the WSGI entry point.
    create_app().run(host="127.0.0.1", port=5000)
