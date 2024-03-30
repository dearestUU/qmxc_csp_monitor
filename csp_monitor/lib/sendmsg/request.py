# _*_ coding:utf-8 _*_


import json
import time
import requests
from requests.models import Response
from urllib3 import disable_warnings
from csp_monitor import logger, logger_r
from csp_monitor.lib.core.enums import HEADERS

disable_warnings()


class WebRequest:
    def __init__(self):
        self.response = Response()
        self.header = HEADERS.web_headers

    @property
    def status_code(self):
        """
        :return: 返回http code
        """
        return self.response.status_code

    @property
    def text(self):
        """将response的内容转换成文本格式"""
        return self.response.text

    @property
    def json(self):
        """将response的内容转换成json格式"""
        try:
            json_data = self.response.content.decode('utf-8', 'ignore')
            return json.loads(json_data)
        except Exception as ex:
            msg = f"响应或解析出现问题.原因: {ex}"
            logger.error(msg)
            logger_r.error(msg)
            return {}

    def request(self, method: str, target_url, header=None, retry_time=3, retry_interval=5, timeout=100, **kwargs):
        """
        :param method: http请求方法
        :param target_url: 目标url
        :param header: 请求头
        :param retry_time: 重连次数
        :param retry_interval: 重连时间间隔
        :param timeout: 网络超时时间
        :return:
        """
        # print(kwargs)
        headers = self.header
        if header and isinstance(header, dict):
            headers.update(header)  # 更新headers中的内容
        while True:
            try:
                if target_url.split(':')[0] not in ('http', 'https'):
                    raise requests.exceptions.MissingSchema
                if method is None:
                    raise Exception("0x09 == Warning:http的请求方法不存在，请填写请求方法后重试!")
                elif method.lower() == "get":
                    self.response = requests.get(url=target_url, headers=headers, timeout=timeout, **kwargs)
                elif method.lower() == "post":
                    self.response = requests.post(url=target_url, headers=headers, timeout=timeout, **kwargs)
                else:
                    raise Exception("0x10 == Warning:填写的http请求方法不支持，目前只有get/post。")
                return self
            except requests.exceptions.MissingSchema:
                print("0x03 == Warning:无效的请求url")
                return self
            except requests.exceptions.InvalidHeader:
                print("0x04 == Warning:无效的Header")
                return self
            except requests.exceptions.ProxyError:
                print("0x05 == Warning:代理出错")
                return self
            except requests.exceptions.InvalidProxyURL:
                print("0x06 == Warning:无效的url代理")
                return self
            except requests.exceptions.SSLError:
                print("0x07 == Warning:SSL错误")
                return self
            except Exception as e:
                print(f"Error: http/https请求出错,正在自动重连，重连次数还剩{retry_time}次，{retry_interval}秒后重试...")
                retry_time -= 1
                if retry_time <= 0:
                    error1 = f"0x08 == Warning:重连失败，请求中断! 请求失败的URL: {target_url} BODY:{kwargs}"
                    logger().error(error1)
                    print(error1)
                    return self
                time.sleep(retry_interval)
