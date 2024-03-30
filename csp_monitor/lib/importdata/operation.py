# _*_ coding:utf-8 _*_

from csp_monitor.lib.mysqlite3.OperationSqlite3 import sqlite


class OPERA:

    explain = "只有新增和删除。没有设计查询和更改"

    @staticmethod
    def opera_insert(table_name, value: tuple) -> bool:
        res = sqlite.insert(table_name=table_name, value=value)
        if res == "SUCCESS":
            return True
        else:
            return False

    @staticmethod
    def opera_delete(table_name, value: str) -> bool:
        res = sqlite.delete(table_name=table_name, value=value)
        if res == "SUCCESS":
            return True
        else:
            return False
