from random import randint
from datetime import datetime
import time
import pandas as pd

from urllib.parse import urlparse

"""
This python file includes utility methods to aid the program flow. Data processing/cleaning are some examples
"""

def clean_urlstr(url):
    """
    Cleans the URL string to make predictions more accurate
    :param url: URL string representation
    :return: clean URL string
    """
    url = url.replace("hxxp", "http")
    if url[-1] == "/":
        url = url[:-1]
    return url

def check_file(file):
    """
    Checks if file is a CSV
    :param file: The file object to check
    :return: True if CSV False if not
    """
    print(file.filename.split('.'))
    if file.filename == "":
        return False
    elif file.filename.split('.')[-1].lower() != 'csv':
        return False
    else:
        return True

def get_today_ordinal():
    dt = datetime.today()
    dt = datetime(*dt.timetuple()[:3])
    return dt.toordinal()

def get_str_ordinal(datestr):
    date_time_obj = datetime.strptime(datestr, '%Y%m%d')
    dt = datetime(*date_time_obj.timetuple()[:3])  # 2013-12-14 00:00:00
    return dt.toordinal()

def generate_csv(dom_dict):
    logfile = pd.read_csv("logfile.csv")
    column_names = ["CaseID", "Date", "Abuse Email", "IPAddress", "Domain", "Target", "URL", "Status"]
    output_df = pd.DataFrame(columns=column_names)

    processed_list = [dom for dom in dom_dict if (dom[1].processed and not dom[1].discard)]

    for index, domain in enumerate(processed_list):
        # if domain[0] not in logfile['Domain']:
        for url_data in domain[1].output():
            output_df = output_df.append(url_data, ignore_index=True)
        # else:
        #     continue

    output_df.to_csv("phish.csv", index=False)
    output_df.to_csv("logfile.csv", mode='a', index=False, header=False)

def filter_log(log, current, days):
    recent_log = log.loc[log['Date'] > get_today_ordinal()-days]
    recent_doms = recent_log['Domain']

    current_domain = current['url'].apply(lambda x: urlparse(x).netloc if x is not float else None)

    print(recent_doms)
    print(current_domain)

    current_filtered = current.loc[~current_domain.isin(recent_doms)]
    print(current_filtered)

    return current_filtered

# log_file = pd.read_csv("logfile.csv")
# curr_file = pd.read_csv("C:\\Users\\jshww\\Documents\\InternCSA2\\AnnexA Folder\\Mar 2021\\Mar 15 - Copy.csv")
# filter_log(log_file, curr_file, 3)

class Domain:
    def __init__(self, domain, ip, url):
        self.domain = domain
        self.ip = [ip]
        self.url = [url]
        self.cnn = 0
        self.rf = 0
        self.live = None

        self.processed = False
        self.discard = False
        self.final_ip = self.ip[0]
        self.final_domain = domain

        self.abuse = None
        self.spoof = None

    def output(self):
        out_list = []
        cn = ["CaseID", "Date", "Abuse Email", "IPAddress", "Domain", "Target", "URL", "Status"]

        case_id = "SingCERT_" + datetime.today().strftime('%Y%m%d') + "-A" + str(randint(100000,999999))

        for url in self.url:
            out_dict = {}
            out_dict.update({cn[0]: case_id})
            out_dict.update({cn[1]: get_today_ordinal()})
            out_dict.update({cn[2]: self.abuse})
            out_dict.update({cn[3]: self.final_ip})
            out_dict.update({cn[4]: self.final_domain})
            out_dict.update({cn[5]: self.spoof})
            out_dict.update({cn[6]: url.url_str})
            out_dict.update({cn[7]: "Active"})
            out_list.append(out_dict)

        return out_list

    def check_benign(self):
        if self.cnn > 50:
            return False
        elif self.rf > 50:
            return False
        elif self.live.cert is None:
            return False
        elif self.live.ocsp != "GOOD":
            return False
        else:
            return True

    def add_url(self, url):
        if url.url_str in [u.url_str for u in self.url]:
            return
        else:
            self.url.append(url)

    def add_ip(self, ip):
        if ip in self.ip:
            return
        else:
            self.ip.append(ip)

    def setlive(self, liveurl):
        self.live = liveurl

    def avg_res(self, model):
        if model == 'cnn':
            self.cnn = int(self.cnn/len(self.url))
        elif model == 'rf':
            self.rf = int(self.rf/len(self.url)*100)

    def __str__(self):
        return str((self.ip, self.url, self.cnn, self.rf))
