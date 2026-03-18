from flask import Flask


def create_app(capture_engine, process_mapper, profiles_dir="profiles"):
    app = Flask(__name__)
    app.config["capture_engine"] = capture_engine
    app.config["process_mapper"] = process_mapper
    app.config["profiles_dir"] = profiles_dir

    from .routes import bp
    app.register_blueprint(bp)

    return app
