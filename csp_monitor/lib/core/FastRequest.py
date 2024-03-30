import asyncio
import platform

import aiohttp
import pandas as pd
from csp_monitor import logger_r
from aiohttp import ClientSession
from csp_monitor.lib.core.setting import PAGE_FIELD, PAGE_PARAM
from csp_monitor.lib.core.CspMethod import split_dev_request_total


async def download_1(url, headers, param, count, countAll, session: ClientSession):
    async with asyncio.Semaphore(5):
        await asyncio.sleep(1)
        try:
            async with session.post(url=url, json=param, headers=headers, ssl=False) as resp:
                return await resp.json(encoding='utf-8'), url, headers, param, countAll, count
        except asyncio.TimeoutError as err:
            msg = f"Timeout: {url} - 总请求: {countAll} - 本次请求:{count}; 原因: {err}"
            logger_r.error(msg)
        except Exception as err1:
            msg = f"Exception: {url} - 总请求: {countAll} - 本次请求:{count}; 原因: {err1}"
            logger_r.error(msg)


async def download_2(paramList):
    """
    :param paramList:
    :return:
    """
    conn = aiohttp.TCPConnector(limit=25, limit_per_host=5)
    UnfinishedPostBody = []  # 服务器响应失败的请求体
    df1 = pd.DataFrame(columns=PAGE_PARAM)
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = []
        for param in paramList:
            url = param[0]
            headers = param[1]
            post_body = param[2]
            countAll = param[3]
            count = param[4]
            tasks.append(asyncio.ensure_future(download_1(url=url, headers=headers, param=post_body, session=session, countAll=countAll, count=count)))

        for resp in await asyncio.gather(*tasks, return_exceptions=True):
            var1 = resp[0]
            var2 = resp[1]
            var3 = resp[2]
            var4 = resp[3]
            var5 = resp[4]
            var6 = resp[5]
            if var1 is None:
                UnfinishedPostBody.append([var2, var3, var4, var5, var6])
            else:
                if 'code' in var1 and var1['code'] == 200 and 'msg' in var1 and var1['msg'] == "OK" and "success" in var1 and var1['success'] == True:
                    data = var1['data']['records']
                    devIp = str(var2).split("https://")[1].split('/')[0]
                    df2 = pd.DataFrame(data=data, columns=PAGE_FIELD)
                    df2.insert(loc=0, column='devIp', value=pd.Series([devIp]))
                    df1 = pd.concat([df1, df2], axis=0, ignore_index=False)
                    percent = "%.2f" % (float(var6 / var5) * 100) + "%"
                    logger_r.info(msg=f'{devIp} - 总计: {var5}条, 本次: {var6}条; - 百分比: {str(percent)}')
                else:
                    """说明服务器响应失败"""
                    UnfinishedPostBody.append([var2, var3, var4, var5, var6])
        df1.fillna(method='ffill', inplace=True)
        return df1, UnfinishedPostBody


def download_main(paramList):
    if "windows" in platform.platform().lower():
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # python3.8 以上的windows
        return asyncio.run(download_2(paramList=paramList))
    else:
        return asyncio.run(download_2(paramList=paramList))  # MAC/Linux 对aiohttp兼容性好


class T:

    @staticmethod
    def get_param(beginTime, endTime, **kwargs):
        ___ = []
        __ = split_dev_request_total(beginTime=beginTime, endTime=endTime, **kwargs)
        [___.append(_) for _ in __ if _[4] != 0]   # 判断获取的日志总是是否为 0
        return ___

    @staticmethod
    def split_paramList(paramList):
        union = paramList
        countOfUnion = len(union)
        ___ = []
        if countOfUnion <= 0:
            return []
        else:
            countOfAiohttp = int(countOfUnion / 50) + 1
            a = 0
            b = 50
            for _ in range(0, countOfAiohttp):
                if countOfUnion > 50:
                    countOfUnion -= 50
                    __ = union[a:b]
                    ___.append(__)
                    a += 50
                    b += 50
                else:
                    __ = union[a:]
                    ___.append(__)
            return ___

    @staticmethod
    def T_MAIN(beginTime, endTime, **kwargs):
        ALL_DF = []
        Unfinished = []
        ListOfAiohttp = T.split_paramList(paramList=T.get_param(beginTime=beginTime, endTime=endTime, **kwargs))
        if len(ListOfAiohttp) == 0:
            return None
        else:
            for _ in ListOfAiohttp:
                logger_r.info("开始进行Aiohttp请求.")
                res = download_main(paramList=_)
                res_0 = res[0]
                res_1 = res[1]
                if len(res_1) == 0:
                    ALL_DF.append(res_0)
                else:
                    ALL_DF.append(res_0)
                    Unfinished += res_1
        while 1:
            if len(Unfinished) != 0:
                again = T.split_paramList(paramList=Unfinished)
                Unfinished.clear()
                for __ in again:
                    logger_r.info(msg=f'对未完成的请求体进行请求...')
                    again_1 = download_main(paramList=__)
                    again_2 = again_1[0]
                    again_3 = again_1[1]
                    ALL_DF.append(again_2)
                    Unfinished += again_3
            else:
                break

        if len(ALL_DF) == 0:
            return None
        elif len(ALL_DF) == 1:
            return ALL_DF[0]
        else:
            return pd.concat(ALL_DF, axis=0, ignore_index=False)
