# _*_ coding:utf-8 _*_


from csp_monitor.lib.mysqlite3.OperationSqlite3 import sqlite, SqlFactory
from csp_monitor.lib.queryip import is_valid_domain
from csp_monitor.lib.venuseye.QueryFromVenusEye import Eye, threat_info_domain
from csp_monitor.setting import AutoUpdate, AutoDays
from datetime import datetime

class Q_DOMAIN:
    name = "查询DOMAIN的资产信息"

    @staticmethod
    def query_domain(domain, ts: int, en: str):
        if is_valid_domain(domain=domain):

            sql2 = SqlFactory.query['bl_domain']
            val2 = (domain,)
            exec_res2 = sqlite.execute_select(sql2, val2)

            sql1 = SqlFactory.query['wl_domain']
            val1 = (domain,)
            exec_res1 = sqlite.execute_select(sql1, val1)
            if exec_res1 is None:
                sql2 = SqlFactory.query['eye_domain']
                val2 = (domain,)
                exec_res2 = sqlite.execute_select(sql2, val2)
                if exec_res2 is None:
                    return Q_DOMAIN.qry_domain_from_VenusEye(domain=domain, ts=ts, en=en)
                else:
                    return "domain", 2, threat_info_domain(exec_res2[3])
            elif exec_res2 is not None:
                return "black_domain", 3, "域名黑名单"
            else:
                return "domain", 1, "安全"
        else:
            return "not_domain", 0, ""

    @staticmethod
    def qry_domain_from_VenusEye(domain, ts, en):
        sql1 = SqlFactory.query['eye_domain']
        val1 = (domain,)
        exec_res1 = sqlite.execute_select(sql=sql1, val=val1)
        if exec_res1 is None:
            if Eye().qryInfo_fromApi_domain(domain=domain, timeStamp=ts, eventName=en):
                sql2 = SqlFactory.query['eye_domain']
                val2 = (domain,)
                exec_res2 = sqlite.execute_select(sql=sql2, val=val2)
                if exec_res2 is None:
                    return "domain", -2, ""
                else:
                    return "domain", 2, threat_info_domain(exec_res2[3])
            else:
                return "domain", -2, ""
        else:
            return Q_DOMAIN._auto_update_domain_alive_time_from_eye_ip(exec_res1, domain=domain, ts=ts, en=en)

    @staticmethod
    def _auto_update_domain_alive_time_from_eye_ip(exec_res: tuple, domain, ts, en):
        if AutoUpdate == 1:
            nowTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            creatTime = exec_res[1]
            delta = (datetime.strptime(nowTime, "%Y-%m-%d %H:%M:%S") - datetime.strptime(creatTime, "%Y-%m-%d %H:%M:%S"))
            if delta.days >= AutoDays:
                exec_res1 = sqlite.delete(table_name="eye_domain", value=domain)
                if exec_res1 == "SUCCESS":
                    if Eye().qryInfo_fromApi_domain(domain=domain, timeStamp=ts, eventName=en):
                        sql2 = SqlFactory.query['eye_domain']
                        val2 = (domain,)
                        exec_res2 = sqlite.execute_select(sql=sql2, val=val2)
                        if exec_res2 is None:
                            return "domain", -2, ""
                        else:
                            return "domain", 2, threat_info_domain(exec_res2[3])
                    else:
                        return "domain", -2, ""
                else:
                    return "domain", -2, ""
            else:
                return "domain", 2, threat_info_domain(exec_res[3])
        else:
            return "domain", 2, threat_info_domain(exec_res[3])
