# _*_ coding:utf-8 _*_

import base64
import json
import random
from datetime import datetime

from csp_monitor import logger_r, logger
from csp_monitor.lib.sendmsg.request import WebRequest
from csp_monitor.lib.mysqlite3.OperationSqlite3 import sqlite
from csp_monitor.lib.utils.convert import time_
from csp_monitor.lib.venuseye.Algorithm import AES_II
from csp_monitor.setting import VENUS_RULE_NUM, VENUS_SOFTWARE_NUM, proxy_change, proxies, VENUES_EYE_TOKEN, VENUS_FLAG


def check_status_code(code) -> str:

    if code == 200:
        return "响应成功"
    elif code == 401:
        return "无权限"
    elif code == 403:
        return "查询失败"
    elif code == 404:
        return "查无记录"
    elif code == 409:
        return "请求次数超限"
    elif code == 501:
        return "查询参数异常"
    elif code == 504:
        return "查询参数过多"
    else:
        return "位置错误"

def threat_info_domain(threat_score: int) -> str:
    if 0 <= threat_score <= 9:
        return "安全"
    elif 10 <= threat_score <= 29:
        return "未知"
    elif 30 <= threat_score <= 59:
        return "低危"
    elif 60 <= threat_score <= 79:
        return "中危"
    else:
        return "高危"

def threat_info_ip(judge: tuple):
    threat_score = judge[3]
    country = judge[10]
    province = judge[11]
    city = judge[12]
    isp = judge[13]
    if 0 <= threat_score <= 9:
        return ('安全-' + country + '-' + province + '-' + city + '-' + isp).replace('--', '-').replace('---', '-')
    elif 10 <= threat_score <= 29:
        return ('未知-' + country + '-' + province + '-' + city + '-' + isp).replace('--', '-').replace('---', '-')
    elif 30 <= threat_score <= 59:
        return ('低危-' + country + '-' + province + '-' + city + '-' + isp).replace('--', '-').replace('---', '-')
    elif 60 <= threat_score <= 79:
        return ('中危-' + country + '-' + province + '-' + city + '-' + isp).replace('--', '-').replace('---', '-')
    else:
        return ('高危-' + country + '-' + province + '-' + city + '-' + isp).replace('--', '-').replace('---', '-')


def save_venuesEye_data_to_sqlite3(table_name: str, value: tuple) -> bool:
    res = sqlite().insert(table_name=table_name, value=value)
    if res == "SUCCESS":
        return True
    else:
        return False

class Eye:
    explain = "目前只实现了查询IP/查域名/PDNS的; VenusEye提供的接口也可查询URL和样本信息."

    ip_api = "https://api.venuseye.com.cn/v2/advanced/common/ip"
    domain_api = "https://api.venuseye.com.cn/v2/advanced/common/domain"
    url_api = "https://api.venuseye.com.cn/v2/advanced/common/url"
    hash_api = "https://api.venuseye.com.cn/v2/advanced/common/hash"
    pdns_api = "https://api.venuseye.com.cn/v2/advanced/common/ip/pdns"

    def __init__(self):
        self.req = WebRequest()

    @property
    def _headers(self) -> dict:
        return {'signature': VENUES_EYE_TOKEN, 'Content-Type': 'application/x-www-form-urlencoded'}

    def _http_request(self, url, data):
        if proxy_change == "on":
            choice_proxy = random.choice(proxies)
            go_proxy = {'http': choice_proxy, 'https': choice_proxy}
            resp = self.req.request("POST", target_url=url, proxies=go_proxy, header=self._headers, data=data, verify=False)
        else:
            resp = self.req.request("POST", target_url=url, header=self._headers, data=data, verify=False)
        return resp

    @staticmethod
    def _returnInfo(ts, en) -> dict:
        return {
            'v': VENUS_RULE_NUM,
            't': ts,
            's': VENUS_SOFTWARE_NUM,
            'e': en
        }

    @staticmethod
    def _return_data(flag, field, timeStamp, eventName):
        if flag == 1:
            info = json.dumps(Eye._returnInfo(ts=timeStamp, en=eventName)).replace(" ", "")
            encrypt = AES_II().crp_str(info)
            ex = str(base64.b64encode(encrypt).decode("utf-8").replace("+", '%2B'))
            return 'resource=' + field + '&' + 'ex=' + ex
        else:
            return 'resource=' + field

    def qryInfo_fromApi_ip(self, ip, timeStamp: int = None, eventName: str = None) -> bool:
        data = Eye._return_data(flag=VENUS_FLAG, field=ip, timeStamp=timeStamp, eventName=eventName)
        try:
            resp = self._http_request(url=Eye.ip_api, data=data)
            if resp.status_code == 200:
                try:
                    content = resp.json
                    code = content['status_code']
                    status_code = check_status_code(code=int(code))
                    if status_code == "响应成功":
                        returnData = content['data']
                        update_time = time_(returnData['update_time'])
                        threat_score = int(returnData['threat_score'])
                        tags = str(returnData['tags'])
                        mal_ports = str(returnData['mal_ports'])
                        ip_type = returnData['ip_type']
                        categories = str(returnData['categories'])
                        families = str(returnData['families'])
                        organizations = str(returnData['organizations'])
                        country = returnData['country']
                        province = returnData['province']
                        city = returnData['city']
                        isp = returnData['isp']
                        latitude = str(returnData['latitude'])
                        longitude = str(returnData['longitude'])
                        insert_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        venus_data = (ip, insert_time, update_time, threat_score, tags, mal_ports, ip_type, categories, families, organizations, country, province, city, isp, latitude, longitude)
                        if save_venuesEye_data_to_sqlite3(table_name="eye_ip", value=venus_data):
                            return True
                        else:
                            err4 = f"响应VenusEye的数据成功，但在写入sqlite3中`eye_ip`表时出错! 查询的IP为: {ip}"
                            logger_r.error(err4)
                            logger.error(err4)
                            return False
                    else:
                        err3 = f"VenusEye服务器响应值错误。查询IP: {ip} ; 错误代码: {code}-{status_code}"
                        logger_r.error(msg=err3)
                        logger.error(msg=err3)
                        return False
                except Exception as ex2:
                    err2 = f"解析VenusEye返回的数据时出错! 返回的数据: {str(resp.text)}具体原因: {ex2}"
                    logger_r.error(err2)
                    logger.error(err2)
                    return False
            else:
                raise Exception
        except Exception as ex1:
            err1 = f"VenusEye服务器IP查归属响应出错！要么网络有问题，要么就是VenusEye宕机！具体原因: {ex1}"
            logger_r.error(msg=err1)
            logger.error(msg=err1)
            return False

    def qryInfo_fromApi_domain(self, domain, timeStamp: int = None, eventName: str = None) -> bool:
        data = Eye._return_data(flag=VENUS_FLAG, field=domain, timeStamp=timeStamp, eventName=eventName)
        try:
            resp = self._http_request(url=Eye.domain_api, data=data)
            if resp.status_code == 200:
                try:
                    content = resp.json
                    code = content['status_code']
                    status_code = check_status_code(code=int(code))
                    if status_code == "响应成功":
                        returnData = content['data']
                        this_domain = returnData['domain']
                        update_time = time_(returnData['update_time'])
                        threat_score = int(returnData['threat_score'])
                        tags = str(returnData['tags'])
                        domain_main = returnData['domain_main']
                        categories = str(returnData['categories'])
                        families = str(returnData['families'])
                        organizations = str(returnData['organizations'])
                        insert_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        venus_data = (this_domain, insert_time, update_time, threat_score, tags, domain_main, categories, families, organizations)
                        if save_venuesEye_data_to_sqlite3(table_name="eye_domain", value=venus_data):
                            return True
                        else:
                            err4 = f"响应VenusEye的数据成功，但在写入sqlite3中`eye_domain`表时出错! 查询的domain为: {this_domain}"
                            logger_r.error(err4)
                            logger.error(err4)
                            return False
                    else:
                        err3 = f"VenusEye服务器响应值错误。查询domain: {domain} ; 错误代码: {code}-{status_code}"
                        logger_r.error(msg=err3)
                        logger.error(msg=err3)
                        return False
                except Exception as ex2:
                    err2 = f"解析VenusEye返回的数据时出错! 返回的数据: {str(resp.text)}具体原因: {ex2}"
                    logger_r.error(err2)
                    logger.error(err2)
                    return False
            else:
                raise Exception
        except Exception as ex1:
            err1 = f"VenusEye服务器IP查归属响应出错！要么网络有问题，要么就是VenusEye宕机！具体原因: {ex1}"
            logger_r.error(msg=err1)
            logger.error(msg=err1)
            return False
