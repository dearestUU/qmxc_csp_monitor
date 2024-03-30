# _*_ coding:utf-8 _*_

"""
-------------------------------------------------
@Author: dearest
@Data: 2024/1/20 03:39
@File: is_ban_ip.py
@Version: 1.0.0
@Description: TODO
@Question: NO
-------------------------------------------------
"""
from datetime import datetime
from csp_monitor.lib.mysqlite3.OperationSqlite3 import SqlFactory, sqlite
from csp_monitor.lib.queryip import ipv4_or_ipv6, is_valid_ip
from csp_monitor.setting import Asset

def _qryIp_from_inner(ip):
    """
    :param ip: 在 at_inner 这个库中查询是不是存在
    :return:
    """
    res = sqlite().is_exists(table_name='at_inner', value=ip)
    if res is True:
        return "YES"
    else:
        return "NO"

def _qryIp_inner_or_outer(ip):
    """
    :param ip: 判断ip是内网IP还是外网IP
    :return:
    """
    res = _qryIp_from_inner(ip=ip)
    if res == "YES":
        return "内网"
    else:  # 不存在的话，在配置文件里面找
        if ipv4_or_ipv6(ip=ip) == "ipv6":
            return "IPV6"
        else:
            _ = ip.split('.')
            var1 = _[0] + '.' + _[1] + '.' + _[2] + '.' + _[3]
            var2 = _[0] + '.' + _[1] + '.' + _[2] + '.'
            var3 = _[0] + '.' + _[1] + '.'
            var4 = _[0] + '.'
            if var1 in Asset:
                return "内网"
            elif var2 in Asset:
                return "内网"
            elif var3 in Asset:
                return "内网"
            elif var4 in Asset:
                return "内网"
            else:
                return "外网"

class BAN:

    @staticmethod
    def BanIp(ip, creat_time, reason: str,ban_days: int, ban_ip_address: str,eventName: str) -> bool:
        """
        :param eventName: 待封堵IP的事件名
        :param ban_ip_address: 待封堵IP的地址
        :param ip: 待封堵的IP
        :param creat_time: 封堵的时间
        :param reason: 封堵的理由
        :param ban_days: 封堵的时间  ban_days 等于0 说明这个IP要被永久封堵！
        :return:
        """
        if is_valid_ip(ip=ip):
            origin = _qryIp_inner_or_outer(ip=ip)  # 封堵的这个ip是内网还是外网，亦或是IPV6
            res = sqlite.is_exists(table_name='ban_ip', value=ip)
            if isinstance(res, bool):
                if res is True:  # 说明之前封堵过，现在查询封堵的时长
                    sql1 = SqlFactory.query['ban_ip']
                    val1 = (ip,)
                    exec_res = sqlite.execute_select(sql=sql1, val=val1)
                    ban_count_ = exec_res[6]
                    comment_ = exec_res[9]

                    if ban_days > 0:
                        now_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        creat_time__ = now_time
                        ban_days__ = ban_days
                        ban_count__ = ban_count_ + 1
                        comment__ = comment_ + f";第{ban_count__}次封堵{ban_days__}天-封堵时间{creat_time__}"

                        sql2 = SqlFactory.update['ban_ip']
                        val2 = (creat_time__, reason, ban_days__, ban_count__, ban_ip_address,eventName, comment__, f"封堵{ban_days}天", ip)
                        if sqlite.execute_update(sql=sql2,val=val2):
                            return True
                        else:
                            return False
                    else:
                        creat_time__ = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        ban_days__ = ban_days
                        ban_count__ = ban_count_ + 1
                        comment__ = comment_ + f";第{ban_count__}次永久封堵-封堵时间{creat_time__}"

                        sql2 = SqlFactory.update['ban_ip']
                        val2 = (creat_time__, reason, ban_days__, ban_count__, ban_ip_address, eventName, comment__, f"永久封堵", ip)
                        if sqlite.execute_update(sql=sql2,val=val2):
                            return True
                        else:
                            return False
                else:
                    sql3 = SqlFactory.insert['ban_ip']
                    if ban_days <= 0:
                        val3 = (ip, creat_time, reason, ban_days, origin, creat_time, 1, ban_ip_address, eventName, f"第1次封堵时间{creat_time}", "永久封堵")
                    else:
                        val3 = (ip, creat_time, reason, ban_days, origin, creat_time, 1, ban_ip_address, eventName, f"第1次封堵时间{creat_time}", f"封堵{ban_days}天")
                    if sqlite.execute_update(sql=sql3, val=val3):
                        return True
                    else:
                        return False
            else:
                return False
        else:
            return False
