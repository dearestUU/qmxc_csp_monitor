import json
import random
from datetime import datetime

from csp_monitor import logger, logger_r
from csp_monitor.lib.core.enums import HEADERS
from csp_monitor.lib.sendmsg.request import WebRequest
from csp_monitor.setting import proxies, proxy_change, fs_webhook1, fs_webhook2, fs_webhook3


class Feishu:

    def __init__(self):
        self.header = {"Content-Type": "application/json;charset=utf-8"}

    @property
    def headers(self):
        headers = HEADERS.web_headers
        headers.update(self.header)
        return headers

    def http_request(self, url, data, message):
        web = WebRequest()
        if proxy_change == "on":
            http_proxy = random.choice(proxies)
            self.resp = web.request("post", target_url=url, proxies={'http': http_proxy, 'https': http_proxy}, header=self.headers, json=data)
        else:
            self.resp = web.request("post", target_url=url, header=self.headers, json=data)
        try:
            if self.resp.status_code == 200:
                content = self.resp.json
                # print(content)
                if 'StatusMessage' in content and content['StatusMessage'] == 'success' and 'StatusCode' in content and content['StatusCode'] == 0:
                    logger_r.info(msg=f"Feishu send message success, content: {message} ")
                else:
                    raise Exception
            else:
                raise Exception
        except Exception as ex:
            msg = f"0x14 == Feishu send message Exception. reason: {ex}"
            logger.error(msg=msg)

    def text_wai(self, message):
        data = {
            "msg_type": "text",
            "content": {"text": message}
        }
        if fs_webhook1.startswith('https://open.feishu.cn/open-apis/bot/v2/hook/'):
            self.http_request(url=fs_webhook1, data=data, message=message)
        else:
            pass

    def text_nei(self, message):
        data = {
            "msg_type": "text",
            "content": {"text": message}
        }
        if fs_webhook2.startswith('https://open.feishu.cn/open-apis/bot/v2/hook/'):
            self.http_request(url=fs_webhook2, data=data, message=message)
        else:
            pass

    def error(self, message):
        data = {
            "msg_type": "text",
            "content": {"text": message}
        }
        if fs_webhook3.startswith('https://open.feishu.cn/open-apis/bot/v2/hook/'):
            self.http_request(url=fs_webhook3, data=data, message=message)
        else:
            pass

    def new_green_card(self, msg: list):
        var0 = msg[0]
        var1 = msg[1]
        var2 = msg[2]
        var3 = msg[3]
        var4 = msg[4]
        var5 = msg[5]
        var6 = msg[6]
        var7 = msg[7]
        var8 = msg[8]
        var9 = msg[9]
        var10 = msg[10]
        var11 = msg[11]
        var12 = msg[12]
        var13 = msg[13]
        var14 = msg[14]
        var15 = msg[15]
        var16 = msg[16]
        var17 = msg[17]
        data = {
            "elements": [
                {
                    "tag": "column_set",
                    "flex_mode": "none",
                    "background_style": "grey",
                    "columns": [
                        {
                            "tag": "column",
                            "width": "weighted",
                            "weight": 1,
                            "vertical_align": "top",
                            "elements": [
                                {
                                    "tag": "markdown",
                                    "content": f"**dev:**   {var17}\n️**time:**  {var16[11:19]}"
                                }
                            ]
                        },
                        {
                            "tag": "column",
                            "width": "weighted",
                            "weight": 1,
                            "vertical_align": "top",
                            "elements": [
                                {
                                    "tag": "markdown",
                                    "content": f"**sip:**  {var0}\n**dip:**  {var2}"
                                }
                            ]
                        }
                    ]
                },
                {
                    "tag": "hr"
                },
                {
                    "tag": "markdown",
                    "content": f"**❗️sip归属:** {var1}\n**❗️dip归属:** {var3}\n\n**时间1:** {var4}\n**设备1:** {var5}\n**事件1:** {var6}\n**次数1:** {var7}\n\n**时间1:** {var8}\n**设备2:** {var9}\n**事件2:** {var10}\n**次数2:** {var11}\n\n**时间3:** {var12}\n**设备3:** {var13}\n**事件3:** {var14}\n**次数3:** {var15}"
                },
                {
                    "tag": "hr"
                },
                {
                    "tag": "note",
                    "elements": [
                        {
                            "tag": "plain_text",
                            "content": "❗️dev: 告警设备             ~                   time: 告警时间\n❗️sip: 源IP                      ~                   dip: 目的IP\n❗️1: 表示当天    ~    2: 表示当月    ~    3: 表示近两月\n"
                        }
                    ]
                },
                {
                    "tag": "hr"
                }
            ],
            "header": {
                "template": "green",
                "title": {
                    "content": f"🔥   {var16[0:10]}  告警",
                    "tag": "plain_text"
                }
            }
        }
        last_data = {
            "msg_type": "interactive",
            "card": data
        }
        if fs_webhook1.startswith('https://open.feishu.cn/open-apis/bot/v2/hook'):
            self.http_request(url=fs_webhook1, data=last_data, message=msg)
        else:
            pass

    def new_red_card(self,msg:list):
        var0 = msg[0]
        var1 = msg[1]
        var2 = msg[2]
        var3 = msg[3]
        var4 = msg[4]
        var5 = msg[5]
        var6 = msg[6]
        var7 = msg[7]
        var8 = msg[8]
        var9 = msg[9]

        data = {
            "msg_type": "interactive",
            "card": {
                "config": {"wide_screen_mode": True}, "elements": [{"fields": [
                    {"is_short": True, "text": {"content": f"**设备**\n{var0}", "tag": "lark_md"}},
                    {"is_short": True, "text": {"content": f"**告警时间**\n{var5}", "tag": "lark_md"}},
                    {"is_short": True, "text": {"content": f"\r**源IP**\n{var1}", "tag": "lark_md"}},
                    {"is_short": True, "text": {"content": f"\r**目的IP**\n{var2}", "tag": "lark_md"}},
                    {"is_short": True, "text": {"content": f"\r**事件名称**\n{var3}", "tag": "lark_md"}},
                    {"is_short": True, "text": {"content": f"\r**事件等级**\n{var4}", "tag": "lark_md"}},
                    {"is_short": True,"text": {"content": f"\r**源IP归属**\n{var6}", "tag": "lark_md"}},
                    {"is_short": True, "text": {"content": f"\r**目的IP归属**\n{var7}", "tag": "lark_md"}},
                    {"is_short": True, "text": {"content": f"\r**源&目的**\n{var8}", "tag": "lark_md"}},
                    {"is_short": True, "text": {"content": f"\r**原因**\n{var9}", "tag": "lark_md"}}],
                    "tag": "div"}, {"tag": "hr"}, {"elements":
                    [{
                        "content": "！！！引起重视",
                        "tag": "lark_md"}],
                    "tag": "note"}],
                "header": {"template": "red", "title": {"content": f"{var5[0:10]} 触发黑名单", "tag": "plain_text"}}
            }
        }
        if fs_webhook1.startswith('https://open.feishu.cn/open-apis/bot/v2/hook'):
            self.http_request(url=fs_webhook1, data=data, message=msg)
        else:
            pass

