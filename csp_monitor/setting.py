# _*_ coding:utf-8 _*_
"""
-------------------------------------------------------------------------------------------
@Author: dearest
@Data: 2023/06/17 12:00:00
@File: setting.py
@Version: 1.0.0
@Description: 程序配置文件
-------------------------------------------------------------------------------------------
"""


"""
CSP设备的 IP:Cookie。如果有多个设备，按照列表的格式添加，如 devList = [[ip,cookie],[ip,cookie],[ip,cookie]]
"""

devList = [
           ['13.6.9.58', 'JSESSIONID=14PrKqmSKvK8gBQNg_ASviB3D9GDAsIcpJUdjbCS; satoken=87ef71b61ef944d288aae8dd435fb2d0'],
           ['13.6.9.44', 'JSESSIONID=RlCTLqKB0SJxJ28YHt6ZlzusxMnD9lkbpd_IhREP; satoken=bff3e90cc7ac424fb761b1cb9d50cd12'],
           ['13.6.9.45', 'JSESSIONID=-v8IP0vC4Z2YLaWpU-Tmb0aHYrhtV1P99yukHURC; satoken=86afe80a527c4144906be648a9dd66e6'],
           ['13.6.9.71','JSESSIONID=BbrLhfKMJMWPkoMIwlrHR6CDCfhujWr9uIitgsSy; satoken=5f53fc1985224839bea1bdcbafb983f2']
    ]

"""
机器人的webhook.全都是飞书, 现在没有钉钉了
"""

fs_webhook1 = ""  # 外网CSP群->发送已自动封堵的IP群  eg: https://open.feishu.cn/open-apis/bot/v2/hook/
fs_webhook2 = ""  # 内网CSP群->发送卡片消息  eg: https://open.feishu.cn/open-apis/bot/v2/hook/
fs_webhook3 = ""  # csp脚本异常监控群 eg: https://open.feishu.cn/open-apis/bot/v2/hook/

dd_webhook = ""
dd_webhook1 = ""  # 外网CSP群->发送已自动封堵的IP群
dd_webhook2 = ""  # 内网CSP群->发送markdown消息
dd_webhook3 = ""  # csp脚本异常监控群

"""
标记在sqlite3中的at_outer、at_inner表，在本文件的Asset字段中查询到的资产
"""
tag_area = '中国-陕西省-'


"""
内网出网代理; on开,off关
"""
proxies = ["", ""]  # eg: http://10.10.10.10:8080
proxy_change = "off"  # on开,off关

"""
VenusEye-启明火花情报威胁分析中心提供 TOKEN/密钥。
"""
AutoUpdate = 1  # 1表示自动更新，其他数字表示不用自动更新 IP/Domain。每隔15天后，如果还能查询到该IP/Domain就更新
AutoDays = 30  # 表示超过多少天就自动更新 IP/Domain
VENUES_EYE_TOKEN = ""  # 原本的密钥
VENUS_EYE_SECRET_KEY = ""
VENUS_FLAG = 1   # 标志位。数字1 代表回传给VenuesEye数据。其他数字代表不回传
VENUS_RULE_NUM = ''   # CSP的规则库版本号，用于回传数据给 VenusEye
VENUS_SOFTWARE_NUM = ''  # CSP软件版本号，用于回传数据给 VenusEye

FIREWALL_HOST = ""   # 防火墙侧主机
FIREWALL_PORT = 22   # 防火墙侧端口
FIREWALL_USER = ""  # 防火墙账号
FIREWALL_PASS = ""   # 防火墙密码
FIREWALL_PATH_1 = ""  # 防火墙处理日志的路径
FIREWALL_PATH_2 = ""  # 防火墙处理日志的路径


# redis 数据库 redis-数据库配置文件中的设置
redis_host = '127.0.0.1'  # redis的IP
redis_port = '65530'  # redis的端口，和redis.conf中的端口保持一致
redis_password = ''  # redis的密码，和redis.conf中的端口保持一致

# IP端黑名单
IP_NETWORK_BLACK = ['192.168.', '172.16.', '10.']  # 通常应用在内网网段

# 暴露面资产字典，通常是某个网段 eg: "118.32.":"暴露面网段"
GW_Asset = {
    "": ""
}

# 内网资产字典，按如下方式录入，是为了找查询内网资产归属的，如果通过接口的方式或者其他方式查询的资产归属的，可以不配置
Asset = {
    '': '',
}
