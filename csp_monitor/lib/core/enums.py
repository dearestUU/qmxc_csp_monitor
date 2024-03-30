class LOGGING_LEVELS:
    NOTSET = 0
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class CUSTOM_LOGGING:
    SYSINFO = 21
    SUCCESS = 22
    ERROR = 23
    WARNING = 24


class HEADERS:
    csp_headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9,da;q=0.8,en;q=0.7",
        "Content-Type": "application/json;charset=UTF-8",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "sec-ch-ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"'
    }

    web_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122",
        "Connection": "keep-alive",
    }
