# from urlclass import *
# from model import *

#Delete later
import pandas as pd
import time

from flask import Flask, render_template, request
from flask_socketio import SocketIO, send, emit

app = Flask(__name__,
            static_url_path='',
            static_folder='./static',
            template_folder='./templates')

app.config['SECRET_KEY'] = 'annexA'
socketio = SocketIO(app)

nav_list = ["Upload", "Analyze", "Process", "Export"]

def main():
    csv_df = pd.read_csv("./data/testset.csv")
    cnc_df = csv_df[(csv_df['type'] == 'c&c')]
    phish_df = csv_df[(csv_df['type'] == 'phishing')]

    for url in phish_df['url'].unique():
        send(url)
        time.sleep(0.5)
        # url_obj = LiveUrl(url)
        # print(url_obj.url_str, get_rfprediction(url_obj), get_cnnprediction(url_obj))

@app.route('/', methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return render_template('upload.html', nav_list=nav_list, nav_index=0)
    else:
        print(request.files)
        return "Posted data!"

@app.route('/analyze', methods=["GET", "POST"])
def analyze():
    if request.method == "GET":
        return render_template('index.html', nav_list=nav_list, nav_index=1)
    else:
        return "Posted data!"

@app.route('/process')
def process():
    return render_template('index.html', nav_list=nav_list, nav_index=2)

@socketio.on('processing')
def process_csv(data):
    main()
    print('received message: ' + str(data))


if __name__ == '__main__':
    socketio.run(app, debug=True)
