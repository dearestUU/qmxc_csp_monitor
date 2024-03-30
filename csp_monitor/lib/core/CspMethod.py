from csp_monitor import logger, logger_r
from csp_monitor.lib.core.CspConfig import CSP
from csp_monitor.setting import devList
from csp_monitor.lib.sendmsg.request import WebRequest
from csp_monitor.lib.core.enums import HEADERS


def dev_status():
    for dev in devList:
        ip = dev[0]
        cookie = dev[1]
        url = CSP.status_url(ip=ip)
        headers = HEADERS.csp_headers
        headers.update({"Cookie": cookie})
        try:
            resp = WebRequest().request(method="get", target_url=url, header=headers, verify=False)
            if resp.status_code == 200:
                res = resp.json
                code = res['code']
                success = res['success']
                if code == 200 and success is True:
                    runtime = res['data']['runtime']
                    memoryUsage = res['data']['memoryUsage']
                    cpuUsage = res['data']['cpuUsage']
                    storageUsage = res['data']['storageUsage']
                    operatingTemperature = res['data']['operatingTemperature']
                    out = f"CSP: {ip}\n设备运行时长: {runtime}\n内存使用率:{memoryUsage}%\nCPU使用率: {cpuUsage}%\n硬盘使用率: {storageUsage}%\n系统温度: {operatingTemperature}"
                    print(out)
                    print('>>> >>> >>> >>> >>> >>> >>> >>> >>> >>> >>> >>> >>> >>> >>>')
                else:
                    raise Exception
            else:
                raise Exception
        except Exception as ex:
            msg = f">>> 0x01 == 请求{ip}的设备状态出错!先检查Session 是否失效! 原因: {ex}"
            logger.error(msg)
            logger_r.error(msg)


def single_dev_logs(ip, cookie, beginTime, endTime, **kwargs):
    url = CSP.page_url(ip=ip)
    headers = HEADERS.csp_headers
    headers.update({'Cookie': cookie})
    param = CSP.param_of_onlyTotal(beginTime=beginTime, endTime=endTime, **kwargs)
    # print(param)
    try:
        resp = WebRequest().request(method='post', target_url=url, header=headers, json=param, verify=False).json
        if resp == {}:
            raise Exception
        elif 'data' not in resp and 'total' not in resp:
            raise Exception
        else:
            return resp['data']['total']
    except Exception as ex:
        msg = f'`获取 {ip}` 的日志条数出错.原因: {ex}'
        logger.error(msg=msg)
        logger_r.error(msg=msg)
        return 0


def merge_dev_logs_total(beginTime, endTime, **kwargs) -> dict:
    logs = {}
    for _ in devList:
        ip = _[0]
        cookie = _[1]
        num = single_dev_logs(ip=ip, cookie=cookie, endTime=endTime, beginTime=beginTime, **kwargs)
        ip_cookie = (ip, cookie)
        logs.update({ip_cookie: num})
        logger_r.info(msg=f"`{ip}` - {beginTime} - {endTime} - {num} 条.")
    return logs


def split_dev_request_total(beginTime, endTime, **kwargs) -> list:
    ALL_PARAMS = []
    res = merge_dev_logs_total(beginTime=beginTime, endTime=endTime,**kwargs)
    for key, value in res.items():
        ip = key[0]
        cookie = key[1]
        number = value
        url = CSP.page_url(ip=ip)
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9,da;q=0.8,en;q=0.7",
            "Content-Type": "application/json;charset=UTF-8",
            "Cookie": cookie,
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "sec-ch-ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"'
        }
        if number <= 5000:
            param = CSP.param_of_page(beginTime=beginTime, endTime=endTime, pageNum=1, pageSize=number, **kwargs)
            ALL_PARAMS.append([url, headers, param, number, number])
        else:
            var1 = 0
            for num in range(1, int(number / 5000)+2):
                var1 += 1
                if var1*5000 < number:
                    pageSize = 5000
                    param = CSP.param_of_page(beginTime=beginTime, endTime=endTime, pageNum=num, pageSize=pageSize, **kwargs)
                else:
                    pageSize = number - (var1 - 1) * 5000
                    param = CSP.param_of_page(beginTime=beginTime, endTime=endTime, pageNum=num, pageSize=pageSize, **kwargs)
                ALL_PARAMS.append([url, headers, param, number, pageSize])
    if len(ALL_PARAMS) > 0:
        return ALL_PARAMS
    else:
        return []