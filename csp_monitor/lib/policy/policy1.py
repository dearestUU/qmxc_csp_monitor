# _*_ coding:utf-8 _*_

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from collections import OrderedDict
import pandas as pd
from dateutil.relativedelta import relativedelta
from pandas import DataFrame
from csp_monitor.lib.myredis.ConnectRedis import RC
from csp_monitor.lib.utils.convert import time_, threatLevel_


class P1:
    name = "处理策略：源IP是内网, 目的IP是内网"
    explain = "由于源、目的都是内网IP，所有没有封堵的概念"

    @staticmethod
    def policy(df: DataFrame):
        shi_wu_bao = []
        fei_wu_bao = []
        connection_pool = RC.redis_connect_db1()
        connection_pool_0 = RC.redis_connect_db0_pool()

        with ThreadPoolExecutor(max_workers=50) as executor:
            future = [executor.submit(P1.__policy_util, var, connection_pool, connection_pool_0) for var in df.itertuples()]
            for f in future:
                res = f.result()
                if res[-1] == "shi_wu_bao":
                    shi_wu_bao.append(res[0])
                else:
                    fei_wu_bao.append(res[0])
        return shi_wu_bao, fei_wu_bao

    @staticmethod
    def __policy_util(var, conn, conn1):
        devIp = getattr(var, 'devIp')
        srcIp = getattr(var, 'srcIp')
        destIp = getattr(var, 'destIp')
        signature = getattr(var, 'signature')
        threatLevel = getattr(var, 'threatLevel')
        timeStamp = getattr(var, 'timeStamp')
        srcPort = getattr(var, 'srcPort')
        destPort = getattr(var, 'destPort')
        eventUrl = getattr(var, 'eventUrl')
        eventHost = getattr(var, 'eventHost')
        eventXff = getattr(var, 'eventXff')
        eventXri = getattr(var, 'eventXri')
        appProto = getattr(var, 'appProto')
        proto = getattr(var, 'proto')
        count = getattr(var, 'count')
        sip_add = getattr(var, 'sip_add')[2]
        dip_add = getattr(var, 'dip_add')[2]
        # result = getattr(var, 'result')

        key1_name1 = f"{srcIp}_{destIp}_{signature}"
        key2_name2 = f"{srcIp}_*_{signature}"
        key3_name3 = f"*_{destIp}_{signature}"
        key4_name4 = f"{srcIp}_{destIp}_*"

        # print(sip_add,dip_add)

        if conn.exists(key1_name1) == 1:
            FLAG = P1.__policy_util_1(key1_name1, conn, devIp, signature, timeStamp, srcPort, destPort, eventUrl, eventHost, eventXff, eventXri, appProto, proto, count)
        elif conn.exists(key2_name2) == 1:
            FLAG = P1.__policy_util_1(key2_name2, conn, devIp, signature, timeStamp, srcPort, destPort, eventUrl, eventHost, eventXff, eventXri, appProto, proto, count)
        elif conn.exists(key3_name3) == 1:
            FLAG = P1.__policy_util_1(key3_name3, conn, devIp, signature, timeStamp, srcPort, destPort, eventUrl, eventHost, eventXff, eventXri, appProto, proto, count)
        elif conn.exists(key4_name4) == 1:
            FLAG = P1.__policy_util_1(key4_name4, conn, devIp, signature, timeStamp, srcPort, destPort, eventUrl, eventHost, eventXff, eventXri, appProto, proto, count)
        else:
            FLAG = False

        threatLevel = threatLevel_(level=threatLevel)
        timeStamp = time_(A=timeStamp[0])
        eventUrl = "" if len(eventUrl) == 0 else eventUrl

        transport_data = [devIp, srcIp, destIp, sip_add, dip_add, signature, threatLevel, timeStamp, srcPort, destPort, eventUrl, eventHost, eventXff, eventXri, appProto, proto, count, "源IP&目的IP内网"]
        analysis_result = P1.__policy_util_2(conn=conn1, data=transport_data)
        all_result = transport_data + analysis_result

        if FLAG is True:
            return all_result, "shi_wu_bao"
        else:
            return all_result, "fei_wu_bao"

    @staticmethod
    def __policy_util_1(key: str, conn, devIp, signature, timeStamp, srcPort, destPort, eventUrl, eventHost, eventXff, eventXri, appProto, proto, count) -> bool:
        value = conn.get(key)
        value = json.loads(value)
        v_devIp = value['devIp']
        v_signature = value['signature']
        v_firstTimeStamp = value['firstTimeStamp']
        v_lastTimeStamp = value['lastTimeStamp']
        v_srcPort = value['srcPort']
        v_destPort = value['destPort']
        v_eventUrl = value['eventUrl']
        v_eventHost = value['eventHost']
        v_eventXff = value['eventXff']
        v_eventXri = value['eventXri']
        v_appProto = value['appProto']
        v_proto = value['proto']
        v_count = value['count']

        timeStamp_1 = time_(timeStamp[0])
        timeStamp_2 = time_(timeStamp[-1])

        if (devIp in v_devIp) or ("*" in v_devIp):
            if (signature == v_signature) or (v_signature == "*"):
                if ("*" == v_firstTimeStamp) or ("*" == v_lastTimeStamp) or (v_firstTimeStamp <= timeStamp_1 <= timeStamp_2 <= v_lastTimeStamp):
                    if (srcPort in v_srcPort) or ("*" in v_srcPort):
                        if (destPort in v_destPort) or ("*" in v_destPort):
                            if (eventUrl in v_eventUrl) or ("*" in v_eventUrl):
                                if (eventHost in v_eventHost) or ("*" in v_eventHost):
                                    if (eventXff in v_eventXff) or ("*" in v_eventXff):
                                        if (eventXri in v_eventXri) or ("*" in v_eventXri):
                                            if (appProto in v_appProto) or ("*" in v_appProto):
                                                if (proto in v_proto) or ("*" in v_proto):
                                                    if (count <= v_count) or (v_count == 0):
                                                        return True
                                                    else:
                                                        return False
                                                else:
                                                    return False
                                            else:
                                                return False
                                        else:
                                            return False
                                    else:
                                        return False
                                else:
                                    return False
                            else:
                                return False
                        else:
                            return False
                    else:
                        return False
                else:
                    return False
            else:
                return False
        else:
            return False

    @staticmethod
    def __policy_util_2(conn,data:list) -> list:

        key = f"{data[1]}_{data[2]}"
        name_day = f"{datetime.strptime(data[7][0:10],'%Y-%m-%d').strftime('%Y-%m-%d')}".split('-')
        name_day = 'day-' + name_day[0] + '-' + name_day[1].lstrip('0') + '-' + name_day[2].lstrip('0')

        name_month = f"{datetime.strptime(data[7][0:7], '%Y-%m').strftime('%Y-%m')}".split('-')
        name_month = 'month-' + name_month[0] + '-' + name_month[1].lstrip('0')

        name_two_month = f"{(datetime.strptime(data[7][0:7], '%Y-%m') + relativedelta(months=-1)).strftime('%Y-%m')}".split('-')
        name_two_month = 'month-' + name_two_month[0] + '-' + name_two_month[1].lstrip('0')

        if conn.hexists(name=name_day,key=key) is True:
            value_day = json.loads((conn.hget(name=name_day, key=key)))
            devIp_day = ', '.join(list(value_day.keys()))

            res1 = list(value_day.values())
            new_df = pd.DataFrame(res1)
            timeStr_day = new_df['timeStamp'].values[0][0]

            signature_day = '; '.join([val for sublist in new_df['signature'].values.tolist() for val in sublist])
            count_day = sum(new_df['count'].values.tolist())
        else:
            devIp_day = ""
            signature_day = ""
            timeStr_day = ""
            count_day = 0

        if conn.hexists(name=name_month, key=key) is True:
            value_month = json.loads((conn.hget(name=name_month, key=key)))
            devIp_month = ', '.join(list(value_month.keys()))

            res1 = list(value_month.values())
            new_df1 = pd.DataFrame(res1)
            timeStr_month = new_df1['timeStamp'][0][0]
            signature_month = '; '.join([val for sublist in new_df1['signature'].values.tolist() for val in sublist])
            count_month = sum(new_df1['count'].values.tolist())
        else:
            devIp_month = ""
            signature_month = ""
            timeStr_month = ""
            count_month = 0

        if conn.hexists(name=name_two_month, key=key) is True:
            value_2_month = json.loads((conn.hget(name=name_two_month, key=key)))
            devIp_2_month = ', '.join(list(OrderedDict.fromkeys(devIp_month.split(', ') + list(value_2_month.keys()))))

            res1 = list(value_2_month.values())
            new_df2 = pd.DataFrame(res1)
            timeStr_2_month = new_df2['timeStamp'][0][0]
            signature_2_month = '; '.join(list(OrderedDict.fromkeys(signature_month.split('; ') + [val for sublist in new_df2['signature'].values.tolist() for val in sublist])))
            count_2_month = sum(new_df2['count'].values.tolist()) + count_month
        else:
            devIp_2_month = devIp_month
            signature_2_month = signature_month
            count_2_month = count_month
            timeStr_2_month = timeStr_month
        return [timeStr_day, devIp_day,signature_day,count_day,timeStr_month, devIp_month,signature_month,count_month,timeStr_2_month,devIp_2_month,signature_2_month,count_2_month]
