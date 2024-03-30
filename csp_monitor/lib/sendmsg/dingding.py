import random

from csp_monitor import logger_r, logger
from csp_monitor.lib.core.enums import HEADERS
from csp_monitor.lib.sendmsg.request import WebRequest
from csp_monitor.setting import proxy_change, proxies, dd_webhook1, dd_webhook2, dd_webhook3


class DingDing:

    def __init__(self):
        self.header = {"Content-Type": "application/json;charset=utf-8"}

    @property
    def headers(self):
        headers = HEADERS.web_headers
        headers.update(self.header)
        return headers

    def http_request(self, url, data, message):
        """
        :param message:
        :param url:  请求的url
        :param data: post的body数据
        :return: 主要是为了区分 走代理还是不走代理
        """
        web = WebRequest()
        if proxy_change == "on":
            http_proxy = random.choice(proxies)
            self.resp = web.request("post", target_url=url, proxies={'http': http_proxy, 'https': http_proxy},
                                    header=self.headers, json=data)
        else:
            self.resp = web.request("post", target_url=url, header=self.headers, json=data)
        try:
            if self.resp.status_code == 200:
                content = self.resp.json
                if 'errcode' in content and content['errcode'] == 0 and 'errmsg' in content and content[
                    'errmsg'] == 'ok':
                    logger_r.info(msg=f"DingDing send message success, content: {message} ")
                else:
                    raise Exception
            else:
                raise Exception
        except Exception as ex:
            msg = f"0x14 == DingDing send message Exception. reason: {ex}"
            logger.error(msg=msg)

    def markdown(self, message: list):
        """
        直接发送卡片消息 time_now, time_30, sip, sip_add, dip, dip_add, eventName_1, eventName_30, count_30, count_1, sport_1, dport_1, level_1
        """
        var0 = message[0]  # 发现时间
        var1 = message[1]  # 30_时间
        var2 = message[2]  # sip
        var3 = message[3]  # sip_address
        var4 = message[4]  # dip
        var5 = message[5]  # dip_address
        var6 = message[6]  # eventName_1
        var7 = message[7]  # eventName_30
        var8 = message[8]  # count_30
        var9 = message[9]  # count_1

        title = f"内网CS {var0} 告警"
        content = f'### CS内网{var0[:10]}监测告警\n##### 源IP:{var2}\n##### 目的IP:{var4}\n##### IP归属:\n - 源IP: {var3}\n - 目的: {var5}\n##### 告警时间:\n - 抓取时间: {var0}\n - 30天第一次时间 {var1}\n##### 告警次数\n - 当天次数: {var9}\n - 30天所有次数: {var8}\n##### 告警事件\n - 当天事件: {var6}\n - 30天所有事件: {var7}'

        data = {
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": content
            }
        }
        self.http_request(url=dd_webhook1, data=data,message=f"Send event of {var2}_{var4} SUCCESS.")

        if dd_webhook2.startswith('https://oapi.dingtalk.com/'):
            self.http_request(url=dd_webhook2, data=data, message=f"Send event of {var2}_{var4} SUCCESS.")
        else:
            pass

    def text_wai(self,message):
        pass

    def test_nei(self,message):
        pass