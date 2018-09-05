from flask import Flask, render_template, request
from Ciphers import *

app = Flask(__name__)


@app.route('/')
def main():
    return render_template('main.html')


@app.route('/caesar_encryption', methods=["GET", "POST"])
def caesar_e():
    get_form = None
    if request.method == "GET":
        get_form = True
        return render_template('caesar.e.html', gf=get_form)

    if request.method == "POST":
        get_form = False
        pt = request.form.get('plaintext')
        shift = request.form.get('shift')
        new_cipher = CaesarCipher(plaintext=pt, decryption_shift=shift)
        return render_template('caesar.e.html', gf=get_form, nc=new_cipher)


@app.route('/caesar_decryption', methods=["GET", "POST"])
def caesar_d():
    get_form = None
    if request.method == "GET":
        get_form = True
        return render_template('caesar.d.html', gf=get_form)

    if request.method == "POST":
        get_form = False
        ct = request.form.get('ciphertext')
        shift = request.form.get('shift')
        new_cipher = CaesarCipher(ciphertext=ct, decryption_shift=shift)
        return render_template('caesar.d.html', gf=get_form, nc=new_cipher)


@app.route('/vigener_encryption', methods=["GET", "POST"])
def vigener_e():
    get_form = None
    if request.method == "GET":
        get_form = True
        return render_template('vigener_e.html', gf=get_form)

    if request.method == "POST":
        get_form = False
        pt = request.form.get('plaintext')
        key = request.form.get('key')
        new_cipher = VigenèreCipher(plaintext=pt, start_key=key)
        return render_template('vigener_e.html', gf=get_form, nc=new_cipher)


@app.route('/vigener_decryption', methods=["GET", "POST"])
def vigener_d():
    get_form = None
    if request.method == "GET":
        get_form = True
        return render_template('vigener_d.html', gf=get_form)

    if request.method == "POST":
        get_form = False
        pt = request.form.get('pt')
        ct = request.form.get('ct')
        key = request.form.get('key')
        new_cipher = VigenèreCipher(pt, ct, key)
        return render_template('vigener_d.html', gf=get_form, nc=new_cipher)



if __name__ == '__main__':
    app.run()
