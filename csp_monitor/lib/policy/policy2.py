# _*_ coding:utf-8 _*_

from concurrent.futures import ThreadPoolExecutor
from pandas import DataFrame

from csp_monitor.lib.queryip.ip_or_domain import ip_or_domain
from csp_monitor.lib.utils.convert import time_,threatLevel_


class P2:
    name = "处理策略：源IP是外网&目的IP是内网"

    @staticmethod
    def policy(df: DataFrame):
        BAN = []
        UNBAN = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            future = [executor.submit(P2.__policy_util, var) for var in df.itertuples()]
            for f in future: res = f.result(); BAN.append(res[0]) if res[-1] == "ban" else UNBAN.append(res[0])
        return BAN, UNBAN

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
        _16 = getattr(var, 'sip_add')[2].strip('\n').strip('\r')
        _17 = getattr(var, 'dip_add')[2].strip('\n').strip('\r')
        _18 = getattr(var, 'result')
        comment = ""

        if _18 == 0:
            _18 = "源和目的IP-ipv6"
        elif _18 == 1:
            _18 = "源IP是内网&目的IP是内网"
        elif _18 == 2:
            _18 = "源IP是外网&目的IP是内网"
        elif _18 == 3:
            _18 = "源IP是外网&目的IP是外网"
        elif _18 == 4:
            _18 = "源IP是内网&目的IP是外网"
        else:
            _18 = "源IP或目的IP-都不是个ip"

        if str(_16).startswith('安全-'):
            comment = ""
        else:
            if '中国-' not in str(_16):
                comment = "源IP-非中国IP"
            else:
                if '-陕西省' not in str(_16):
                    comment = "源IP-非陕西IP"
                else:
                    if str(_16).startswith('高危'):
                        comment = f"源IP-VenusEye查询高危"
                    elif str(_16).startswith('中危'):
                        comment = f"源IP-VenusEye查询中危"
                    else:
                        if _5 >= 40:
                            comment = f"源IP-高危事件-{_4}"
                        else:
                            var = P2.policy_util_2(host=_10, xff=_11, xri=_12, eventName=_4, timeStamp=_6[0])
                            if var is not None:
                                comment = "源IP-" + var
                            else:
                                comment = ""

        if comment != "":
            # comment="" 表示这是要封堵的IP
            return [_1, _2, _3, _4, threatLevel_(_5), time_(int(_6[0])), _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, comment], "ban"
        else:
            return [_1, _2, _3, _4, threatLevel_(_5), time_(int(_6[0])), _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, comment], "unban"

    @staticmethod
    def policy_util_1(host_xff_xri, eventName, timeStamp):
        for var in str(host_xff_xri).split(','):
            if var != "":
                var1 = ip_or_domain(field=var, eventName=eventName, timeStamp=timeStamp)
                if var1.startswith('高危'):
                    return var, '高危'
                elif var1.startswith('中危'):
                    return var, '中危'
                elif var1.startswith('黑名单'):
                    return var, '域名黑名单'
        return None

    @staticmethod
    def policy_util_2(host, xff, xri, eventName, timeStamp):
        host_result = P2.policy_util_1(host_xff_xri=host, eventName=eventName, timeStamp=timeStamp)
        if host_result is None:
            xff_result = P2.policy_util_1(host_xff_xri=xff, eventName=eventName, timeStamp=timeStamp)
            if xff_result is None:
                xri_result = P2.policy_util_1(host_xff_xri=xri, eventName=eventName, timeStamp=timeStamp)
                if xri_result is None:
                    return None
                else:
                    return f"XRI-{xri_result[-1]}-{xri_result[0]}"
            else:
                return f"XFF-{xff_result[-1]}-{xff_result[0]}"
        else:
            return f"HOST-{host_result[-1]}-{host_result[0]}"
