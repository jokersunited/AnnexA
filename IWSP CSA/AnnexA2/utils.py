from flask_socketio import SocketIO, send, emit
import time

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

class Domain:
    def __init__(self, domain, ip, url):
        self.domain = domain
        self.ip = [ip]
        self.url = [url]
        self.cnn = 0
        self.rf = 0
        self.live = None

        self.processed = False

    def add_url(self, url):
        if url in [u.url_str for u in self.url]:
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
