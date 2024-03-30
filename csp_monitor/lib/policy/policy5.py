# _*_ coding:utf-8 _*_

from concurrent.futures import ThreadPoolExecutor
from pandas import DataFrame
from csp_monitor.lib.utils.convert import time_,threatLevel_

class P5:
    name = "处理策略：源IP和目的都是ipv6"

    @staticmethod
    def policy(df: DataFrame):
        NOTHING_TO_DO = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            future = [executor.submit(P5.__policy_util, var) for var in df.itertuples()]
            for f in future:
                res = f.result()
                NOTHING_TO_DO.append(res)
        return NOTHING_TO_DO

    @staticmethod
    def __policy_util(var):
        _1 = getattr(var, 'devIp')
        _2 = getattr(var, 'srcIp')
        _3 = getattr(var, 'destIp')
        _4 = getattr(var, 'signature')
        _5 = getattr(var, 'threatLevel')
        _6 = getattr(var, 'timeStamp')
        _7 = getattr(var, 'srcPort')
        _8 = getattr(var, 'destPort')
        _9 = getattr(var, 'eventUrl')
        _10 = getattr(var, 'eventHost')
        _11 = getattr(var, 'eventXff')
        _12 = getattr(var, 'eventXri')
        _13 = getattr(var, 'appProto')
        _14 = getattr(var, 'proto')
        _15 = getattr(var, 'count')
        _16 = getattr(var, 'sip_add')[2]
        _17 = getattr(var, 'dip_add')[2]
        # _18 = getattr(var, 'result')
        _18 = "源或目的-不是个IP"
        comment = "WARNING"
        return [_1, _2, _3, _4, threatLevel_(_5), time_(int(_6[0])), _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, comment]
