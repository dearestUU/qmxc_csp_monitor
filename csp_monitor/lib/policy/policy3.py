# _*_ coding:utf-8 _*_

from pandas import DataFrame
from concurrent.futures import ThreadPoolExecutor
from csp_monitor.lib.policy.policy2 import P2
from csp_monitor.lib.utils.convert import time_,threatLevel_


def from_where(A: int):
    if A == 0:
        return "配置文件"
    elif A == 1:
        return "外网资产"
    elif A == 2:
        return "内网资产"
    elif A == 3:
        return "venusEye"
    elif A == -1:
        return "ipv6没搜到"
    elif A == -2:
        return "venusEye查询出问题"
    elif A == -3:
        return "这不是个IP"
    else:
        return "ERROR"

class P3:
    name = "处理策略：源IP是外网&目的IP是外网"

    @staticmethod
    def policy(df: DataFrame):
        BAN_SIP = []
        UNBAN_SIP = []
        BAN_DIP = []
        UNBAN_DIP = []
        UNBAN = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            future = [executor.submit(P3.__policy_util, var) for var in df.itertuples()]
            for f in future:
                res = f.result()
                res_1 = res[-1]
                res_2 = res[0]
                if res_1 == "ban-sip":
                    BAN_SIP.append(res_2)
                elif res_1 == "ban-dip":
                    BAN_DIP.append(res_2)
                elif res_1 == "unban-sip":
                    UNBAN_SIP.append(res_2)
                elif res_1 == "unban-dip":
                    UNBAN_DIP.append(res_2)
                else:
                    UNBAN.append(res_2)
        return BAN_SIP, BAN_DIP, UNBAN_SIP, UNBAN_DIP, UNBAN

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
        _16 = getattr(var, 'sip_add')
        _17 = getattr(var, 'dip_add')
        _18 = "源IP是外网&目的IP是外网"
        comment = ""
        comment1 = ""
        comment2 = ""

        sip_add_from_where = _16[1]
        dip_add_from_where = _17[1]

        sip_add = _16[2].strip('\n').strip('\r')
        dip_add = _17[2].strip('\n').strip('\r')


        if (sip_add_from_where == 3) and (dip_add_from_where in (0,1)):
            if str(sip_add).startswith('安全-'):
                comment1 = ""
            else:
                if '中国-' not in str(sip_add):
                    comment1 = "源IP-非中国IP"
                else:
                    if '-陕西省' not in str(sip_add):
                        comment1 = "源IP-非陕西IP"
                    else:
                        if str(sip_add).startswith('高危'):
                            comment1 = f"源IP-VenusEye查询高危"
                        elif str(sip_add).startswith('中危'):
                            comment1 = f"源IP-VenusEye查询中危"
                        else:
                            if _5 >= 40:
                                comment1 = f"源IP-高危事件-{_4}"
                            else:
                                var = P2.policy_util_2(host=_10, xff=_11, xri=_12, eventName=_4, timeStamp=_6[0])
                                if var is not None:
                                    comment1 = "源IP-" + var
                                else:
                                    comment1 = ""

            if comment1 == "":
                return [_1, _2, _3, _4, threatLevel_(_5), time_(int(_6[0])), _7, _8, _9, _10, _11, _12, _13, _14, _15, sip_add, dip_add, _18, comment1], "unban-sip"
            else:
                return [_1, _2, _3, _4, threatLevel_(_5), time_(int(_6[0])), _7, _8, _9, _10, _11, _12, _13, _14, _15, sip_add, dip_add, _18, comment1], "ban-sip"
        elif (sip_add_from_where in (0, 1)) and (dip_add_from_where == 3):
            if str(dip_add).startswith('安全-'):
                comment2 = ""
            else:
                if '中国-' not in str(dip_add):
                    comment2 = "目的IP-非中国IP"
                else:
                    if '-陕西省' not in str(dip_add):
                        comment2 = "目的IP-非陕西IP"
                    else:
                        if str(dip_add).startswith('高危'):
                            comment2 = f"目的IP-VenusEye查询高危"
                        elif str(dip_add).startswith('中危'):
                            comment2 = f"目的IP-VenusEye查询中危"
                        else:
                            if _5 >= 40:
                                comment2 = f"目的IP-高危事件-{_4}"
                            else:
                                var = P2.policy_util_2(host=_10, xff=_11, xri=_12, eventName=_4, timeStamp=_6[0])
                                if var is not None:
                                    comment2 = "目的IP-" + var
                                else:
                                    comment2 = ""

            if comment2 == "":
                return [_1, _2, _3, _4, threatLevel_(_5), time_(int(_6[0])), _7, _8, _9, _10, _11, _12, _13, _14, _15, sip_add, dip_add, _18, comment2], "unban-dip"
            else:
                return [_1, _2, _3, _4, threatLevel_(_5), time_(int(_6[0])), _7, _8, _9, _10, _11, _12, _13, _14, _15, sip_add, dip_add, _18, comment2], "ban-dip"
        else:
            comment = ""
            return [_1, _2, _3, _4, _5, time_(int(_6[0])), _7, _8, _9, _10, _11, _12, _13, _14, _15, sip_add, dip_add, _18, comment], "unban"


