from flask import Flask, jsonify, render_template, request

from analyzer import analyze_message


app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    try:
        report = analyze_message(
            sender=data.get("sender", ""),
            subject=data.get("subject", ""),
            message=data.get("message", ""),
        )
        return jsonify({"success": True, **report})
    except ValueError as error:
        return jsonify({"success": False, "error": str(error)}), 400


if __name__ == "__main__":
    app.run(debug=True)
