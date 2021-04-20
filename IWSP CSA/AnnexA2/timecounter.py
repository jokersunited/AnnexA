from timeit import default_timer as timer
from datetime import timedelta

from urlclass import LiveUrl

url_list = ['https://google.com', 'http://centurytec.com', 'http://hushaisdhaishdas.cisdi']

for url in url_list:
    live = LiveUrl(url)

    start = timer()
    live.get_live()
    end = timer()
    print("requests method: " + str(timedelta(seconds=end-start)))

    start = timer()
    live.get_dns()
    end = timer()
    print("socket method: " + str(timedelta(seconds=end-start)))