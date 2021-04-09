from urlclass import Url, LiveUrl
from model import get_cnnprediction, get_rfprediction
from utils import *

import pandas as pd
import numpy as np

import time

from functools import wraps
from flask import Flask, render_template, request, flash, redirect, url_for, send_file
from flask_socketio import SocketIO, send, emit, join_room

app = Flask(__name__,
            static_url_path='',
            static_folder='./static',
            template_folder='./templates')

app.config['SECRET_KEY'] = 'annexA'
socketio = SocketIO(app, async_mode="threading")

nav_list = ["Upload", "Analyze", "Consolidate", "Export"]
glo_csvfile = None

def reset_instance():
    phish_df = None
    cnc_df = None
    domain_dict = {}

reset_instance()

sock_id = None
cookie = None

def get_unprocessed(dom_dict):
    return [[index+1, dom] for index, dom in enumerate(dom_dict) if not dom[1].processed]

def get_selected(dom_dict):
    return [[index+1, dom] for index, dom in enumerate(dom_dict) if (dom[1].processed and not dom[1].discard)]

def send_log(msg):
    socketio.send(msg)

def clean_csv(csv_df):
    global phish_df, cnc_df, domain_dict
    log_file = pd.read_csv("logfile.csv")

    domain_dict = {}

    cnc_df = csv_df[(csv_df['type'] == 'c&c')].drop_duplicates(subset='domain name')
    cnc_df["domain name"].replace({np.nan: "unknown"}, inplace=True)
    cnc_df = cnc_df[['ip', 'asn', 'domain name']]
    cnc_df.rename(columns={'domain name': 'domain_name'}, inplace=True)
    cnc_df['date'] = datetime.today().strftime('%Y-%m-%d')
    cnc_df = cnc_df[['ip', 'date', 'asn', 'domain_name']]

    cnc_df.to_csv("cnc.csv", index=False)

    phish_df_unclean = csv_df[(csv_df['type'] == 'phishing')]

    phish_df = filter_log(log_file, phish_df_unclean, 3)

    if len(phish_df_unclean['domain name'].drop_duplicates()) > len(phish_df['domain name'].drop_duplicates()):
        flash(str(len(phish_df_unclean['domain name'].drop_duplicates())-len(phish_df['domain name'].drop_duplicates()))
              + " domain(s) were automatically removed as they were recently recorded in the past 3 days.", "success")

    for row in phish_df.itertuples():
        url = clean_urlstr(row.url)
        url = Url(url)
        if row[6] not in domain_dict:
            if type(row[6]) is float:
                domain_dict.update({url.get_domain(): Domain(url.get_domain(), row.ip, url)})
            else:
                domain_dict.update({row[6]: Domain(row[6], row.ip, url)})
                domain_dict.update({row[6]: Domain(row[6], row.ip, url)})
        else:
            domain_dict[row[6]].add_url(url)
            domain_dict[row[6]].add_ip(row.ip)

    down_list = []
    dup_list = []
    for index, value in enumerate(domain_dict.values()):
        send_log({'text': 'Processing - ' + str(value.domain), 'prog': int((index+1)/len(domain_dict.values())*100)})
        value.url.sort(key=lambda x: len(x.url_str))
        for url in value.url:
            value.rf += get_rfprediction(url)
            value.cnn += get_cnnprediction(url)
        value.avg_res('rf')
        value.avg_res('cnn')
        send_log({'text': 'Analyzing - ' + str(value.url[0].url_str)})
        value.setlive(LiveUrl(value.url[0].url_str))

        if not (value.live.access is False or value.live.dns is False):
            value.abuse = value.live.first_email()
            value.spoof = value.live.get_spoofed()
        else:
            down_list.append(value.domain)

    flash(str(len(down_list)) + " domain(s) were automatically removed as they were down.", 'success')
    for down in down_list:
        del domain_dict[down]

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
    global glo_csvfile, cookie
    if request.method == "GET":
        return render_template('upload.html', nav_list=nav_list, nav_index=0)
    else:

        if 'csvfile' not in request.files:
            flash('Upload failed!', 'error')
            return redirect(url_for("upload"))

        send_log({'text': 'Verifying captcha & getting Zone-h results'})

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
            if len(domain_dict) == 0:
                flash('No processable phishing domains left!', 'error')
                return redirect(url_for('process'))
            else:
                return render_template('analyze.html', nav_list=nav_list, nav_index=1, domain_dictfull=domain_dict,
                                   selected=get_selected(domain_dict), unprocessed=get_unprocessed(domain_dict),
                                   domain_dict=domain_dict[int(domid)-1], dom_count=len(domain_dict), domid=int(domid))

        elif request.method == "POST" and int(domid) > 0:
            domain_dict[int(domid) - 1][1].final_ip = request.form['ip']
            domain_dict[int(domid) - 1][1].final_domain = request.form['domain']
            domain_dict[int(domid) - 1][1].abuse = request.form['email']
            domain_dict[int(domid) - 1][1].spoof = request.form['target']
            domain_dict[int(domid) - 1][1].discard = False
            domain_dict[int(domid)-1][1].processed = True
            flash("Succesfully Updated!", 'success')
            if int(domid) != len(domain_dict):
                return redirect(url_for("analyze", domid=int(domid) + 1))
            else:
                return redirect(url_for("analyze", domid=domid))

    except (IndexError, TypeError, ValueError) as e:
        raise e
        print(e)
        flash("Invalid domain ID specified", 'error')
        return redirect(url_for("upload"))

    else:
        flash("Invalid request received", 'error')
        return redirect(url_for("upload"))

@app.route('/discard/<domid>', methods=["GET"])
@uploaded_file
def discard(domid):
    domain_dict[int(domid) - 1][1].processed = True
    domain_dict[int(domid)-1][1].discard = True
    flash("Succesfully Discarded!", 'success')
    if int(domid) != len(domain_dict):
        return redirect(url_for("analyze", domid=int(domid)+1))
    else:
        return redirect(url_for("analyze", domid=domid))

@app.route('/recurl/<domid>', methods=["GET"])
@uploaded_file
def recurl(domid):
    send_log({'text': 'Re-analyzing - ' + request.args['url']})
    domain_dict[int(domid) - 1][1].live = LiveUrl(request.args['url'])
    flash("Successfully re-analzyed specified URL", "success")
    return redirect(url_for("analyze", domid=domid))

@app.route('/consolidate')
@uploaded_file
def process():
    global domain_dict
    generate_csv(domain_dict)
    # reset_instance()
    return render_template('consolidate.html', nav_list=nav_list, nav_index=2, timestamp=int(time.time()))

@app.route('/send_file/<file>/<uuid>')
@uploaded_file
def download(file, uuid):
    if file == "phish":
        return send_file('phish.csv',
                             mimetype='text/csv',
                             attachment_filename='phish-' + uuid +".csv",
                             as_attachment=True)
    elif file == "cnc":
        return send_file('cnc.csv',
                         mimetype='text/csv',
                         attachment_filename='cnc-' + uuid +".csv",
                         as_attachment=True)
    else:
        return "NO"

@socketio.on('connect')
def sock_conn():
    global sock_id
    sock_id = request.sid

if __name__ == '__main__':
    socketio.run(app, debug=True)
