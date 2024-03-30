# _*_ coding:utf-8 _*_

from concurrent.futures import ThreadPoolExecutor
from pandas import DataFrame
from csp_monitor.lib.utils.convert import time_, threatLevel_

class P0:
    name = "处理策略：源IP和目的都是ipv6"

    @staticmethod
    def policy(df: DataFrame):
        BAN = []
        UNBAN = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            future = [executor.submit(P0.__policy_util, var) for var in df.itertuples()]
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
        _16 = getattr(var, 'sip_add')
        _17 = getattr(var, 'dip_add')
        # _18 = getattr(var, 'result')
        _18 = "源和目的IP-ipv6"
        comment = ""

        sip_add_from_where = _16[1]
        dip_add_from_where = _17[1]

        sip_add = _16[2].strip('\n').strip('\r')
        dip_add = _17[2].strip('\n').strip('\r')

        if sip_add_from_where in (0, 1):
            # 说明目的IP是高危IP
            if _5 >= 40:
                comment = f"目的IP-高危事件-{_4}"
            else:
                comment = ""
        elif dip_add_from_where in (0,1):
            if _5 >= 40:
                comment = f"源IP-高危事件-{_4}"
            else:
                comment = ""
        else:
            comment = ""

        if comment != "":
            # comment="" 表示这是要封堵的IP
            return [_1, _2, _3, _4, threatLevel_(_5), time_(int(_6[0])), _7, _8, _9, _10, _11, _12, _13, _14, _15, sip_add, dip_add, _18, comment], "ban"
        else:
            return [_1, _2, _3, _4, threatLevel_(_5), time_(int(_6[0])), _7, _8, _9, _10, _11, _12, _13, _14, _15, sip_add, dip_add, _18, comment], "unban"
