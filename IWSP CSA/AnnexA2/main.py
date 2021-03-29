from urlclass import Url, LiveUrl
from model import get_cnnprediction, get_rfprediction
from utils import *
import pandas as pd

import time

from functools import wraps
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_socketio import SocketIO, send, emit, join_room

app = Flask(__name__,
            static_url_path='',
            static_folder='./static',
            template_folder='./templates')

app.config['SECRET_KEY'] = 'annexA'
socketio = SocketIO(app, async_mode="threading")

nav_list = ["Upload", "Analyze", "Consolidate", "Export"]
glo_csvfile = None

phish_df = None
cnc_df = None
domain_dict = {}

sock_id = None

def send_log(msg):
    socketio.send(msg)

def clean_csv(csv_df):
    global phish_df, cnc_df, domain_dict

    domain_dict = {}

    cnc_df = csv_df[(csv_df['type'] == 'c&c')]
    phish_df = csv_df[(csv_df['type'] == 'phishing')]
    for row in phish_df.itertuples():
        url = clean_urlstr(row.url)
        url = Url(url)
        if row[6] not in domain_dict:
            if type(row[6]) is float:
                domain_dict.update({url.get_domain(): Domain(url.get_domain(), row.ip, url)})
            else:
                domain_dict.update({row[6]: Domain(row[6], row.ip, url)})
        else:
            domain_dict[row[6]].add_url(url)
            domain_dict[row[6]].add_ip(row.ip)

    for index, value in enumerate(domain_dict.values()):
        send_log({'text': 'Processing ' + str(value.domain), 'prog': int((index+1)/len(domain_dict.values())*100)})
        value.url.sort(key=lambda x: len(x.url_str))
        for url in value.url:
            value.rf += get_rfprediction(url)
            value.cnn += get_cnnprediction(url)
        value.avg_res('rf')
        value.avg_res('cnn')
        send_log({'text': 'Curling ' + str(value.url[0].url_str)})
        value.setlive(LiveUrl(value.url[0].url_str))

        if not (value.live.access is False or value.live.dns is False):
            value.abuse = value.live.first_email()
            value.spoof = value.live.get_spoofed()

    domain_dict = list(domain_dict.items())
    print(domain_dict)


def uploaded_file(f):
    @wraps(f)
    def upload_check(*args, **kwargs):
        if glo_csvfile is None:
            flash("Please upload a CSV file first!", 'error')
            return redirect(url_for("upload"))
        return f(*args, **kwargs)
    return upload_check

@app.route('/', methods=["GET", "POST"])
def upload():
    global glo_csvfile
    if request.method == "GET":
        return render_template('upload.html', nav_list=nav_list, nav_index=0)
    else:
        if 'csvfile' not in request.files:
            flash('Upload failed!', 'error')
            return redirect(url_for("upload"))
        csvfile = request.files['csvfile']
        if check_file(csvfile):
            glo_csvfile = pd.read_csv(csvfile)
            clean_csv(glo_csvfile)
            return redirect(url_for("analyze", domid=1))
        else:
            flash('Upload failed!', 'error')
            return redirect(url_for("upload"))

@app.route('/analyze/<domid>', methods=["GET", "POST"])
@uploaded_file
def analyze(domid):
    print(request.method)
    try:
        if request.method == "GET" and int(domid) > 0:
            return render_template('analyze.html', nav_list=nav_list, nav_index=1, domain_dictfull=domain_dict, domain_dict=domain_dict[int(domid)-1], dom_count=len(domain_dict), domid=int(domid))
        elif request.method == "POST" and int(domid) > 0:
            domain_dict[int(domid)-1][1].processed = True
            flash("Succesfully Updated!", 'success')
            return redirect(url_for("analyze", domid=domid))
    except (IndexError, TypeError, ValueError) as e:
        print(e)
        raise e
        flash("Invalid domain ID specified", 'error')
        return redirect(url_for("upload"))

    else:
        flash("Invalid request received", 'error')
        return redirect(url_for("upload"))

@app.route('/recurl/<domid>', methods=["GET"])
@uploaded_file
def recurl(domid):
    send_log({'text': 'Re-analyzing - ' + request.args['url']})
    domain_dict[int(domid) - 1][1].live = LiveUrl(request.args['url'])
    return redirect(url_for("analyze", domid=domid))

@app.route('/process')
def process():
    return render_template('index.html', nav_list=nav_list, nav_index=2)

@socketio.on('connect')
def sock_conn():
    global sock_id
    sock_id = request.sid

if __name__ == '__main__':
    socketio.run(app, debug=True)
