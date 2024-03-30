# _*_ coding:utf-8 _*_

from datetime import datetime
from csp_monitor.lib.venuseye.QueryFromVenusEye import threat_info_ip, Eye
from csp_monitor.lib.mysqlite3.OperationSqlite3 import sqlite, SqlFactory
from csp_monitor.lib.queryip import ipv4_or_ipv6
from csp_monitor.setting import Asset, AutoUpdate, AutoDays, GW_Asset
import pandas as pd
from csp_monitor import logger, logger_r

class Q_IP:
    name = "查询IP的归属"

    @staticmethod
    def fetchall_util(sql) -> list:
        res = sqlite.execute_select_many(sql=sql)
        try:
            if res is None:
                return []
            else:
                if len(res) == 0:
                    return []
                else:
                    # 取出第
                    return pd.DataFrame(data=res).iloc[:, 0].tolist()
        except Exception as ex:
            logger.error(msg=f"从数据库取出白名单出错: {ex}")
            return []

    @staticmethod
    def fetchall_event_black() -> list:
        sql = SqlFactory.query['fetchall_event_black']
        return Q_IP.fetchall_util(sql=sql)

    @staticmethod
    def fetchall_sip_black() -> list:
        sql = SqlFactory.query['fetchall_sip_black']
        return Q_IP.fetchall_util(sql=sql)

    @staticmethod
    def fetchall_dip_black() -> list:
        sql = SqlFactory.query['fetchall_dip_black']
        return Q_IP.fetchall_util(sql=sql)

    @staticmethod
    def fetchall_event() -> list:
        sql = SqlFactory.query['fetchall_event']
        return Q_IP.fetchall_util(sql=sql)

    @staticmethod
    def fetchall_sip() -> list:
        sql = SqlFactory.query['fetchall_sip']
        return Q_IP.fetchall_util(sql=sql)

    @staticmethod
    def fetchall_dip() -> list:
        sql = SqlFactory.query['fetchall_dip']
        return Q_IP.fetchall_util(sql=sql)

    @staticmethod
    def query_is_inner(ip: str) -> bool:
        sql = SqlFactory.query['at_inner']
        val = (ip,)
        res = sqlite.execute_select(sql=sql, val=val)
        if res is None:
            var = ipv4_or_ipv6(ip=ip)
            if var == "not_ip":
                return False
            else:
                if var == "ipv6":
                    if var in Asset:
                        return True
                    else:
                        return False
                else:
                    _ = ip.split('.')
                    var1 = _[0] + '.' + _[1] + '.' + _[2] + '.' + _[3]
                    var2 = _[0] + '.' + _[1] + '.' + _[2] + '.'
                    var3 = _[0] + '.' + _[1] + '.'
                    var4 = _[0] + '.'
                    if var1 in Asset:
                        return True
                    elif var2 in Asset:
                        return True
                    elif var3 in Asset:
                        return True
                    elif var4 in Asset:
                        return True
                    else:
                        return False
        else:
            return True

    @staticmethod
    def query_ip(ip, ts: int, en: str):
        res = ipv4_or_ipv6(ip=ip)
        if res == "not_ip":
            return "not_ip", -3, "", ""
        else:
            if res == "ipv6":
                sql1 = SqlFactory.query['at_outer']
                val1 = (ip,)
                exec_res1 = sqlite.execute_select(sql=sql1, val=val1)
                if exec_res1 is None:
                    if ip not in Asset:
                        return "ipv6", -1, "", ""
                    else:
                        return "ipv6", 0, Asset[ip], "内网"
                else:
                    return "ipv6", 1, exec_res1[1], "外网"
            else:
                sql2 = SqlFactory.query['at_inner']
                val2 = (ip,)
                exec_res2 = sqlite.execute_select(sql=sql2, val=val2)
                if exec_res2 is None:
                    _ = ip.split('.')
                    var1 = _[0] + '.' + _[1] + '.' + _[2] + '.' + _[3]
                    var2 = _[0] + '.' + _[1] + '.' + _[2] + '.'
                    var3 = _[0] + '.' + _[1] + '.'
                    var4 = _[0] + '.'
                    if var1 in Asset:
                        return "ipv4", 0, Asset[var1], "内网"
                    elif var2 in Asset:
                        return "ipv4", 0, Asset[var2], "内网"
                    elif var3 in Asset:
                        return "ipv4", 0, Asset[var3], "内网"
                    elif var4 in Asset:
                        return "ipv4", 0, Asset[var4], "内网"
                    else:
                        sql3 = SqlFactory.query['at_outer']
                        val3 = (ip,)
                        exec_res3 = sqlite.execute_select(sql=sql3, val=val3)
                        if exec_res3 is None:
                            sql4 = SqlFactory.query['eye_ip']
                            val4 = (ip,)
                            exec_res4 = sqlite.execute_select(sql=sql4, val=val4)
                            if exec_res4 is None:
                                return Q_IP.qry_ipv4_from_VenusEye(ip=ip, ts=ts, en=en)
                            else:
                                if var1 in GW_Asset:
                                    return "ipv4", 0, GW_Asset[var1], "外网"
                                elif var2 in GW_Asset:
                                    return "ipv4", 0, GW_Asset[var2], "外网"
                                elif var3 in GW_Asset:
                                    return "ipv4", 0, GW_Asset[var3], "外网"
                                elif var4 in GW_Asset:
                                    return "ipv4", 0, GW_Asset[var4], "外网"
                                else:  # 从VenusEye中去查
                                    return "ipv4", 3, threat_info_ip(judge=exec_res4), "外网"
                        else:
                            return "ipv4", 1, exec_res3[1], "外网"
                else:
                    return "ipv4", 2, exec_res2[1], "内网"

    @staticmethod
    def qry_ipv4_from_VenusEye(ip, ts, en):
        sql1 = SqlFactory.query['eye_ip']
        val1 = (ip,)
        exec_res1 = sqlite.execute_select(sql=sql1, val=val1)
        if exec_res1 is None:
            if Eye().qryInfo_fromApi_ip(ip=ip, timeStamp=ts, eventName=en):
                sql2 = SqlFactory.query['eye_ip']
                val2 = (ip,)
                exec_res2 = sqlite.execute_select(sql=sql2, val=val2)
                if exec_res2 is None:
                    return "ipv4", -2, "", ""
                else:
                    return "ipv4", 3, threat_info_ip(judge=exec_res2), "外网"
            else:
                return "ipv4", -2, "", ""
        else:
            return Q_IP._auto_update_ip_alive_time_from_eye_ip(exec_res1, ip=ip, ts=ts, en=en)

    @staticmethod
    def _auto_update_ip_alive_time_from_eye_ip(exec_res: tuple, ip, ts, en):
        if AutoUpdate == 1:
            nowTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            creatTime = exec_res[1]
            delta = (datetime.strptime(nowTime, "%Y-%m-%d %H:%M:%S") - datetime.strptime(creatTime, "%Y-%m-%d %H:%M:%S"))
            if delta.days >= AutoDays:
                exec_res1 = sqlite.delete(table_name='eye_ip', value=ip)
                if exec_res1 == "SUCCESS":
                    if Eye().qryInfo_fromApi_ip(ip=ip, timeStamp=ts, eventName=en):
                        sql2 = SqlFactory.query['eye_ip']
                        val2 = (ip,)
                        exec_res2 = sqlite.execute_select(sql=sql2, val=val2)
                        if exec_res2 is None:
                            return "ipv4", -2, "", ""
                        else:
                            return "ipv4", 3, threat_info_ip(judge=exec_res2), "外网"
                    else:
                        return "ipv4", -2, "", ""
                else:
                    return "ipv4", -2, "", ""
            else:
                return "ipv4", 3, threat_info_ip(judge=exec_res), "外网"
        else:
            return "ipv4", 3, threat_info_ip(judge=exec_res), "外网"

    @staticmethod
    def qry_ip_is_ban(ip: str):
        res = sqlite.is_exists(table_name='ban_ip', value=ip)
        try:
            assert isinstance(res, bool)
            if res is True:
                return True
            else:
                return False
        except AssertionError:
            logger.error('判断IP存不存在于已封堵表格，失败！')
            return False

