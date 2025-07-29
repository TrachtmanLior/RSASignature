# web_app.py
from flask import Flask, render_template, request
from rsasignature.rsa import RSA

app = Flask(__name__)
rsa = None
public_key = None

@app.route("/", methods=["GET", "POST"])
def index():
    global rsa, public_key
    output = {}

    if request.method == "POST":
        action = request.form.get("action")

        if action == "generate":
            rsa = RSA(size=512, primality_test="miller_rabin")
            public_key = rsa.public_key
            output["keys"] = {
                "public": public_key,
            }

        elif action == "sign" and rsa:
            message = request.form.get("message")
            signature = rsa.sign(message)
            output["signature"] = str(signature)

        elif action == "verify" and rsa:
            try:
                sig = int(request.form.get("signature"))
                verified = rsa.verify(sig, public_key)
                output["verified"] = rsa.recover_string(verified).decode()
            except Exception as e:
                output["verify_error"] = f"error: {str(e)}"

    return render_template("index.html", output=output)

if __name__ == "__main__":
    app.run(debug=True)
