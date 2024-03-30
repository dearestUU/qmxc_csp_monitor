# _*_ coding:utf-8 _*_

import sqlite3
from csp_monitor import logger_r
from typing import Union
from csp_monitor.lib.mysqlite3.ConnectSqlite3 import SC

class sqlite:
    name = "操作sqlite3数据库"

    @staticmethod
    def execute_select(sql: str, val: tuple) -> Union[tuple, None]:

        with SC.SC() as connection:
            cursor = connection.cursor()
            try:
                result = cursor.execute(sql, val).fetchone()
            except Exception as ex:
                logger_r.error(f'>>> execute SELECT statement: `{sql}` failed ; value : `{val}` ; reason: {ex}')
                return None
            else:
                return result
            finally:
                cursor.close()

    @staticmethod
    def execute_select_many(sql: str) -> Union[list, None]:
        with SC.SC() as connection:
            cursor = connection.cursor()
            try:
                result = cursor.execute(sql).fetchall()
            except Exception as ex:
                logger_r.error(f'>>> execute SELECT statement: `{sql}` failed ; reason: {ex}')
                return None
            else:
                return result
            finally:
                cursor.close()

    @staticmethod
    def execute_update(sql: str, val: tuple) -> bool:
        with SC.SC() as connection:
            cursor = connection.cursor()
            try:
                cursor.execute(sql, val)
                connection.commit()
            except Exception as ex:
                logger_r.error(f'>>> execute statement: `{sql}` failed ; value : `{str(val)}` ; reason: {ex}')
                return False
            else:
                return True
            finally:
                cursor.close()

    @staticmethod
    def is_exists(table_name, value):
        try:
            sql = f"SELECT COUNT(*) FROM {table_name} WHERE {SqlFactory.primary_key[table_name]} = ?"
            val = (value,)
            result = sqlite.execute_select(sql=sql, val=val)
            if result is None:
                raise Exception
            else:
                return result[0] > 0
        except sqlite3.Error as e:
            msg = f"SQLite error: {e}"
            return msg

    @staticmethod
    def insert(table_name, value: tuple):
        exists = sqlite.is_exists(table_name=table_name, value=value[0])
        if isinstance(exists, bool):
            if exists is True:
                return "SUCCESS"
            else:
                sql = SqlFactory.insert[table_name]
                if sqlite.execute_update(sql=sql, val=value):
                    return "SUCCESS"
                else:
                    return "FALSE"
        else:
            logger_r.error(f"insert failed. {exists}")
            return "FALSE"

    @staticmethod
    def delete(table_name, value: str):
        exists = sqlite.is_exists(table_name=table_name, value=value)
        if isinstance(exists, bool):
            if exists is True:
                sql = SqlFactory.delete[table_name]
                val = (value,)
                if sqlite.execute_update(sql=sql,val=val):
                    return "SUCCESS"
                else:
                    return "FALSE"
            else:
                return "SUCCESS"
        else:
            logger_r.error(f"delete failed. {exists}")
            return "FALSE"


class SqlFactory:
    primary_key = {
        "wl_sip": "sip",
        "wl_dip": "dip",
        "wl_domain": "this_domain",
        "wl_event": "event",
        "bl_sip": "sip",
        "bl_dip": "dip",
        "bl_domain": "this_domain",
        "bl_event": "event",
        "eye_ip": "ip",
        "eye_domain": "this_domain",
        "at_inner": "ip",
        "at_outer": "ip",
        "ban_ip": "ip"
    }

    insert = {
        "wl_sip": f"insert into wl_sip values (?,?,?,?)",
        "wl_dip": f"insert into wl_dip values (?,?,?,?)",
        "wl_domain": f"insert into wl_domain values (?,?,?,?)",
        "wl_event": f"insert into wl_event values (?,?,?,?)",
        "bl_sip": f"insert into bl_sip values (?,?,?,?)",
        "bl_dip": f"insert into bl_dip values (?,?,?,?)",
        "bl_domain": f"insert into bl_domain values (?,?,?,?)",
        "bl_event": f"insert into bl_event values (?,?,?,?)",
        "eye_ip": f"insert into eye_ip values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        "eye_domain": f"insert into eye_domain values (?,?,?,?,?,?,?,?,?)",
        "at_inner": f"insert into at_inner values (?,?,?,?)",
        "at_outer": f"insert into at_outer values (?,?,?,?)",
        "ban_ip": f"insert into ban_ip values (?,?,?,?,?,?,?,?,?,?,?)",
    }

    delete = {
        "wl_sip": f"delete from wl_sip where {primary_key['wl_sip']} = ?",
        "wl_dip": f"delete from wl_dip where {primary_key['wl_dip']} = ?",
        "wl_domain": f"delete from wl_domain where {primary_key['wl_domain']} = ?",
        "wl_event": f"delete from wl_event where {primary_key['wl_event']} = ?",
        "bl_sip": f"delete from bl_sip where {primary_key['bl_sip']} = ?",
        "bl_dip": f"delete from bl_dip where {primary_key['bl_dip']} = ?",
        "bl_domain": f"delete from bl_domain where {primary_key['bl_domain']} = ?",
        "bl_event": f"delete from bl_event where {primary_key['bl_event']} = ?",
        "eye_ip": f"delete from eye_ip where {primary_key['eye_ip']} = ?",
        "eye_domain": f"delete from eye_domain where {primary_key['eye_domain']} = ?",
        "at_inner": f"delete from at_inner where {primary_key['at_inner']} = ?",
        "at_outer": f"delete from at_outer where {primary_key['at_outer']} = ?",
        "ban_ip": f"delete from ban_ip where {primary_key['ban_ip']} = ?",
    }

    update = {
        "ban_ip": f"update ban_ip set creat_time = ?, reason = ?, ban_days = ?, ban_count = ?,ban_ip_address = ?, ip_relate_eventName = ?, comment = ?, comment1 = ? where ip = ?"
    }

    query = {
        "at_outer": f"select * from at_outer where ip = ?",
        "at_inner": f"select * from at_inner where ip = ?",
        "eye_ip": "select * from eye_ip where ip = ?",
        "wl_domain": f"select * from wl_domain where this_domain = ?",
        "eye_domain": "select * from eye_domain where ip = ?",
        "ban_ip":f"select * from ban_ip where ip = ?",
        "fetchall_sip": f"select * from wl_sip",
        "fetchall_dip": f"select * from wl_dip",
        "fetchall_event": f"select * from wl_event",
        "fetchall_event_black": f"select * from bl_event",
        "fetchall_sip_black": f"select * from bl_sip",
        "fetchall_dip_black": f"select * from bl_dip",
        "bl_domain": f"select * from bl_domain where this_domain = ?",
    }

