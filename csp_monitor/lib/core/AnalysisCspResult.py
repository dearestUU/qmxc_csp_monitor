from datetime import datetime
import numpy as np
import pandas as pd
from pandas import DataFrame
from csp_monitor import logger, logger_r
from csp_monitor.lib.core.FastRequest import T
from csp_monitor.lib.core.setting import PAGE_PARAM
from csp_monitor.lib.myredis.ConnectRedis import RC
from csp_monitor.lib.myredis.WriteCspDataToRedis import WTR
from csp_monitor.lib.queryip import ipv4_or_ipv6
from csp_monitor.lib.queryip.query_ip import Q_IP
from concurrent.futures import ThreadPoolExecutor
from csp_monitor.lib.utils.convert import time_
from csp_monitor.setting import IP_NETWORK_BLACK


def m1(x):
    y = x.drop_duplicates().dropna().tolist()
    return '*' if len(y) > 5 else ','.join(map(str, y))


def m2(x):
    return x.drop_duplicates().dropna().tolist()


def m3(x):
    return ','.join(x.drop_duplicates().dropna().tolist())


def m4(x):
    return x.sort_values().iloc[[0, -1]].tolist()


def m5(sip, dip):
    if ipv4_or_ipv6(ip=sip) == "ipv6" and ipv4_or_ipv6(ip=dip) == "ipv6":
        return 0
    elif ipv4_or_ipv6(ip=sip) == "ipv4" and ipv4_or_ipv6(ip=dip) == "ipv4":
        __sip = Q_IP.query_is_inner(ip=sip)
        __dip = Q_IP.query_is_inner(ip=dip)
        if __sip is True and __dip is True:
            return 1
        elif __sip is False and __dip is True:
            return 2
        elif __sip is False and __dip is False:
            return 3
        else:
            return 4
    else:
        return 5


class Analysis:
    @staticmethod
    def page_data(sTime, eTime, **kwargs):
        data = T.T_MAIN(beginTime=sTime, endTime=eTime, **kwargs)
        if data is None:
            logger.info(msg=f"S/{sTime} - E/{eTime} - No Data.")
            return []
        else:
            try:
                Analysis.write_to_redis(sTime=sTime, eTime=eTime, data=data)
            except Exception as e:
                print(f"事件特征存入redis数据库失败!!!reason: {e}")
                logger_r.error(msg=f"事件特征存入redis数据库失败!!!reason: {e}")

            df = pd.DataFrame(data=data, columns=PAGE_PARAM)
            df.insert(loc=13, column='count', value=0)
            df1 = df.groupby(by=['devIp', 'srcIp', 'destIp', 'signature', 'threatLevel'])
            a = df1['srcPort'].apply(m1)
            b = df1['destPort'].apply(m1)
            c = df1['eventUrl'].apply(m2)
            d = df1['eventHost'].apply(m3)
            e = df1['eventXff'].apply(m3)
            f = df1['eventXri'].apply(m3)
            g = df1['appProto'].apply(m3)
            h = df1['proto'].apply(m3)
            i = df1['count'].count()
            j = df1['timeStamp'].apply(m4)
            df2 = pd.concat([j, a, b, c, d, e, f, g, h, i], axis=1, ignore_index=False).reset_index()
            df2.sort_values(by='devIp', ascending=True, inplace=True)
            logger_r.info(msg=f'S/{sTime} - E/{eTime} - Total {df.shape[0]}')
            return df2

    @staticmethod
    def sip_dip(sTime, eTime, **kwargs):
        df = Analysis.page_data(sTime=sTime, eTime=eTime, **kwargs)
        if isinstance(df, list):
            return []
        else:
            SIP_WHITE = Q_IP.fetchall_sip()
            DIP_WHITE = Q_IP.fetchall_dip()
            EVENT_WHITE = Q_IP.fetchall_event()
            df = df[~(df['srcIp'].isin(SIP_WHITE) | df['destIp'].isin(DIP_WHITE) | df['signature'].isin(EVENT_WHITE))]
            with ThreadPoolExecutor(max_workers=50) as executor:
                future1 = [executor.submit(Q_IP.query_ip,var1,var2,var3[0]) for var1,var2,var3 in zip(df['srcIp'],df['signature'],df['timeStamp'])]
                df['sip_add'] = [f.result() for f in future1]

            with ThreadPoolExecutor(max_workers=50) as executor:
                future2 = [executor.submit(Q_IP.query_ip,var1,var2,var3[0]) for var1,var2,var3 in zip(df['destIp'],df['signature'],df['timeStamp'])]
                df['dip_add'] = [f.result() for f in future2]

            with ThreadPoolExecutor(max_workers=50) as executor:
                future2 = [executor.submit(m5, var1, var2) for var1, var2 in zip(df['srcIp'], df['destIp'])]
                df['result'] = [f.result() for f in future2]

            SIP_BLACK = Q_IP.fetchall_sip_black()
            DIP_BLACK = Q_IP.fetchall_dip_black()
            EVENT_BLACK = Q_IP.fetchall_event_black()

            df1 = df[df['srcIp'].isin(SIP_BLACK)].copy()
            df1['comment'] = '源IP在黑名单'
            df2 = df[df['destIp'].isin(DIP_BLACK)].copy()
            df2['comment'] = '目的IP在黑名单'
            df3 = df[df['signature'].isin(EVENT_BLACK)].copy()
            df3['comment'] = '事件名称在黑名单'
            df4 = df[df['srcIp'].apply(lambda x: any(x.startswith(s) for s in IP_NETWORK_BLACK))].copy()
            df4['comment'] = '源IP在黑名单网络段'
            df5 = df[df['destIp'].apply(lambda x: any(x.startswith(s) for s in IP_NETWORK_BLACK))].copy()
            df5['comment'] = '目的IP在黑名单网络段'
            df6 = pd.concat([df1, df2, df3, df4, df5], axis=0)
            df6.drop_duplicates(inplace=True,subset=['devIp','srcIp','destIp','signature'])
            df = df[~(df['srcIp'].isin(SIP_BLACK) | df['destIp'].isin(DIP_BLACK) | df['signature'].isin(EVENT_BLACK) | df['srcIp'].isin(df4['srcIp'].values.tolist()) | df['destIp'].isin(df4['destIp'].values.tolist()))]

            finally_res = {key: value for key, value in df.groupby('result')}
            finally_res.update({6: df6})
            return finally_res

    @staticmethod
    def write_to_redis(sTime,eTime, data):
        df = pd.DataFrame(data=data, columns=PAGE_PARAM)
        df_sorted = df.sort_values(by='timeStamp')  # 按照时间戳排列

        df_sorted['timeStamp'] = df_sorted['timeStamp'].apply(time_)
        df_sorted['by_month'] = df_sorted['timeStamp'].apply(lambda x: f'{datetime.strptime(x, "%Y-%m-%d %H:%M:%S").year}-{datetime.strptime(x, "%Y-%m-%d %H:%M:%S").month}')
        df_sorted['by_day'] = df_sorted['timeStamp'].apply(lambda x: f'{datetime.strptime(x, "%Y-%m-%d %H:%M:%S").year}-{datetime.strptime(x, "%Y-%m-%d %H:%M:%S").month}-{datetime.strptime(x, "%Y-%m-%d %H:%M:%S").day}')

        for month,group in df_sorted.groupby(by='by_month'):
            key_name = f"month-{month}"
            group_month = group[PAGE_PARAM]
            dict_result = Analysis._write_to_redis_utils(df=group_month)
            connection = RC.redis_connect_db0()

            if connection.exists(key_name) == 1:
                WTR.update_to_redis(result=dict_result,connection=connection,conn_db=0,set_name=key_name)
            else:
                WTR.save_to_redis(result=dict_result,connection=connection,conn_db=0,set_name=key_name,sTime=sTime,eTime=eTime, set_day=70)

        for day,group in df_sorted.groupby(by='by_day'):
            key_name = f"day-{day}"
            group_day = group[PAGE_PARAM]
            dict_result = Analysis._write_to_redis_utils(df=group_day)
            connection = RC.redis_connect_db0()
            if connection.exists(key_name) == 1:
                WTR.update_to_redis(result=dict_result,connection=connection,conn_db=0,set_name=key_name)
            else:
                WTR.save_to_redis(result=dict_result,connection=connection,conn_db=0,set_name=key_name,sTime=sTime,eTime=eTime, set_day=15)

    @staticmethod
    def _write_to_redis_utils(df: DataFrame):
        df.insert(loc=13, column='count', value=0)
        df1 = df.groupby(['srcIp', 'destIp', 'devIp'])
        a_ = df1['signature'].apply(m2)
        b_ = df1['threatLevel'].apply(m2)
        c_ = df1['srcPort'].apply(m1)
        d_ = df1['destPort'].apply(m1)
        e_ = df1['eventUrl'].apply(m2)
        f_ = df1['eventHost'].apply(m3)
        g_ = df1['eventXff'].apply(m3)
        h_ = df1['eventXri'].apply(m3)
        i_ = df1['appProto'].apply(m3)
        j_ = df1['proto'].apply(m3)
        k_ = df1['timeStamp'].apply(m4)
        l_ = df1['count'].count()

        df2 = pd.concat([a_, b_, c_, d_, e_, f_, g_, h_, i_, j_, k_, l_], axis=1, ignore_index=False).reset_index()

        dict_result = {}
        np_data = np.array(df2.groupby(by=['srcIp', 'destIp']), dtype=[('index', tuple), ('value', DataFrame)])
        for row in np_data.flat:
            index = row[0]
            value = row[1]
            key_value = {'_'.join(index): {}}
            key_value['_'.join(index)].update({k: v for k, v in zip(value['devIp'],value.drop(['srcIp', 'destIp', 'devIp'], axis=1).to_dict('records'))})
            dict_result.update(key_value)
        return dict_result

