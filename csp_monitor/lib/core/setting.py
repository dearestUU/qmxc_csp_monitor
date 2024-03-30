import os

ROOT_PATH = os.path.abspath(os.path.dirname(__file__)).split('csp_monitor')[0]
LOG_PATH = os.path.join(ROOT_PATH, 'logs')
FILE_PATH = os.path.join(ROOT_PATH, 'file')
HAVE_BAN_EVENT_PATH = os.path.join(FILE_PATH, 'HAVE_BAN_EVENT')
HAVE_BAN_IP_PATH = os.path.join(FILE_PATH, 'HAVE_BAN_IP')
UNBAN_IPV6_PATH = os.path.join(FILE_PATH, 'UNBAN_IPV6')
UNBAN_EVENT_PATH = os.path.join(FILE_PATH, 'UNBAN_EVENT')
EVENT_IN_NEI = os.path.join(FILE_PATH, 'EVENT_IN_NEI')
SQLITE3_PATH = os.path.join(ROOT_PATH, 'csp_monitor', 'asset.db')
CSP_MONITOR_PATH = os.path.join(ROOT_PATH, 'csp_monitor')

FALSE_ALARM = os.path.join(FILE_PATH, 'FALSE_ALARM')
TRUE_ALARM = os.path.join(FILE_PATH, 'TRUE_ALARM')

IP_NOT_RECORD_IN_DB = os.path.join(FILE_PATH, '待封堵IP没有记录到DB')
NOT_IP_PATH = os.path.join(FILE_PATH, '源或目的IP-不是IP')

BLACK_IP_EVENT = os.path.join(FILE_PATH, '黑名单')

PAGE_FIELD = ['timeStamp', 'signature', 'srcIp', 'destIp', 'srcPort', 'destPort', 'threatLevel', 'proto', 'appProto', 'eventHost', 'eventXff', 'eventXri', 'eventUrl', 'id']
PAGE_PARAM = ['devIp', 'timeStamp', 'signature', 'srcIp', 'destIp', 'srcPort', 'destPort', 'threatLevel', 'proto', 'appProto', 'eventHost', 'eventXff', 'eventXri', 'eventUrl', 'id']


def creat_folder():

    print(f"{'* ' * 54}")
    if not os.path.exists(LOG_PATH):
        os.mkdir(LOG_PATH)
        print(f"*{' ' * 47}logs  目录已创建")
    else:
        print(f"*{' ' * 47}logs  目录已存在")

    if not os.path.exists(FILE_PATH):
        os.mkdir(FILE_PATH)
        print(f"*{' ' * 47}file  目录已创建")
    else:
        print(f"*{' ' * 47}file  目录已存在")

    if not os.path.exists(UNBAN_IPV6_PATH):
        os.mkdir(UNBAN_IPV6_PATH)
        print(f"*{' ' * 47}UNBAN_IPV6  目录已创建")
    else:
        print(f"*{' ' * 47}UNBAN_IPV6  目录已存在")

    if not os.path.exists(UNBAN_EVENT_PATH):
        os.mkdir(UNBAN_EVENT_PATH)
        print(f"*{' ' * 47}UNBAN_EVENT_PATH  目录已创建")
    else:
        print(f"*{' ' * 47}UNBAN_EVENT_PATH  目录已存在")

    if not os.path.exists(HAVE_BAN_IP_PATH):
        os.mkdir(HAVE_BAN_IP_PATH)
        print(f"*{' ' * 47}HAVE_BAN_IP_PATH  目录已创建")
    else:
        print(f"*{' ' * 47}HAVE_BAN_IP_PATH  目录已存在")

    if not os.path.exists(HAVE_BAN_EVENT_PATH):
        os.mkdir(HAVE_BAN_EVENT_PATH)
        print(f"*{' ' * 47}HAVE_BAN_EVENT  目录已创建")
    else:
        print(f"*{' ' * 47}HAVE_BAN_EVENT  目录已存在")

    if not os.path.exists(NOT_IP_PATH):
        os.mkdir(NOT_IP_PATH)
        print(f"*{' ' * 47}NOT_IP_PATH  目录已创建")
    else:
        print(f"*{' ' * 47}NOT_IP_PATH  目录已存在")

    if not os.path.exists(IP_NOT_RECORD_IN_DB):
        os.mkdir(IP_NOT_RECORD_IN_DB)
        print(f"*{' ' * 47}IP_NOT_RECORD_IN_DB  目录已创建")
    else:
        print(f"*{' ' * 47}IP_NOT_RECORD_IN_DB  目录已存在")

    if not os.path.exists(FALSE_ALARM):
        os.mkdir(FALSE_ALARM)
        print(f"*{' ' * 47}FALSE_ALARM  目录已创建")
    else:
        print(f"*{' ' * 47}FALSE_ALARM  目录已存在")

    if not os.path.exists(TRUE_ALARM):
        os.mkdir(TRUE_ALARM)
        print(f"*{' ' * 47}TRUE_ALARM  目录已创建")
    else:
        print(f"*{' ' * 47}TRUE_ALARM  目录已存在")

    if not os.path.exists(BLACK_IP_EVENT):
        os.mkdir(BLACK_IP_EVENT)
        print(f"*{' ' * 47}BLACK_IP_EVENT  目录已创建")
    else:
        print(f"*{' ' * 47}BLACK_IP_EVENT  目录已存在")

    print(f"{'* ' * 54}")
