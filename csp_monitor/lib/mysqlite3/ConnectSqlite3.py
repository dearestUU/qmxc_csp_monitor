# _*_ coding:utf-8 _*_


import sqlite3
from sqlite3 import Connection
from csp_monitor.lib.core.setting import SQLITE3_PATH


class SQLiteSingleton:
    _name = "sqlite3 单例模式"
    _instance = None

    def __new__(cls, db_file):
        if cls._instance is None:
            cls._instance = super(SQLiteSingleton, cls).__new__(cls)
            cls._instance._conn = sqlite3.connect(db_file)
        return cls._instance

    def get_connection(self):
        return self._conn


class SC:
    name = "连接 sqlite3数据库"

    @staticmethod
    def sqlite3_connect() -> Connection:
        return SQLiteSingleton(SQLITE3_PATH).get_connection()

    @staticmethod
    def SC() -> Connection:
        return sqlite3.connect(database=SQLITE3_PATH)
