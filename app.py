from flask import Flask, render_template, request
from detector import analyze_input

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    selected_type = "url"
    submitted_input = ""
    email_image_text = ""

    if request.method == "POST":
        selected_type = request.form.get("input_type", "url")

        if selected_type == "url":
            submitted_input = request.form.get("url_input", "").strip()
            if submitted_input:
                result = analyze_input(submitted_input)

        elif selected_type == "email":
            email_body = request.form.get("email_input", "").strip()
            email_image_text = request.form.get("email_image_text", "").strip()

            combined_email = email_body
            if email_image_text:
                combined_email += "\n\n[Image Text]\n" + email_image_text

            submitted_input = email_body
            if combined_email.strip():
                result = analyze_input(combined_email)

    return render_template(
        "index.html",
        result=result,
        selected_type=selected_type,
        submitted_input=submitted_input,
        email_image_text=email_image_text
    )

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/privacy-policy")
def privacy_policy():
    return render_template("privacy_policy.html")

if __name__ == "__main__":
    app.run(debug=True)