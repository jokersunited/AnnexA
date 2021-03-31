# import requests
# 
# resp = requests.get("http://zone-h.org/archive/filter=1/fulltext=1/domain=.sg")
# print(resp.content)

from datetime import datetime, timedelta


dt = datetime.today()
print(dt)
dt = datetime(*dt.timetuple()[:3]) # 2013-12-14 00:00:00
print(dt.toordinal())

date_time_str = '20180629'


print(date_time_obj.timetuple())
print(*date_time_obj.timetuple())
date_time_obj = datetime.strptime(date_time_str, '%Y%m%d')
dt = datetime(*date_time_obj.timetuple()[:3]) # 2013-12-14 00:00:00
print(dt.toordinal())
