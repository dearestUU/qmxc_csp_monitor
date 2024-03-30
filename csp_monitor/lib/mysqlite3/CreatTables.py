# _*_ coding:utf-8 _*_

from csp_monitor.lib.mysqlite3.ConnectSqlite3 import SC

class CT:

    def __init__(self):
        self.connection = SC.sqlite3_connect()  # 创建sqlite3的连接
        self.cursor_creat = self.connection.cursor()  # 创建一个 新增表的游标

    def wl_sip(self):
        # 创建名为 "wl_sip" 的源IP白名单表
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS wl_sip (
                            sip TEXT PRIMARY KEY,
                            creat_time TEXT,
                            origin TEXT,
                            comment TEXT
                        )''')
        self.connection.commit()

    def wl_dip(self):
        # 创建名为 "wl_dip" 的目的IP白名单表
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS wl_dip (
                            dip TEXT PRIMARY KEY,
                            creat_time TEXT,
                            origin TEXT,
                            comment TEXT
                        )''')
        self.connection.commit()

    def wl_domain(self):
        # 创建名为 "wl_domain" 的域名白名单表
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS wl_domain (
                            this_domain TEXT PRIMARY KEY,
                            creat_time TEXT,
                            origin TEXT,
                            comment TEXT
                        )''')
        self.connection.commit()

    def wl_event(self):
        # 创建名为 "wl_event" 的CSP事件白名单表
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS wl_event (
                            event TEXT PRIMARY KEY,
                            creat_time TEXT,
                            origin TEXT,
                            comment TEXT
                        )''')
        self.connection.commit()

    def bl_sip(self):
        # 创建名为 "bl_sip" 的源IP黑名单表
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS bl_sip (
                            sip TEXT PRIMARY KEY,
                            creat_time TEXT,
                            origin TEXT,
                            comment TEXT
                        )''')
        self.connection.commit()

    def bl_dip(self):
        # 创建名为 "bl_dip" 的目的IP黑名单表
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS bl_dip (
                            dip TEXT PRIMARY KEY,
                            creat_time TEXT,
                            origin TEXT,
                            comment TEXT
                        )''')
        self.connection.commit()

    def bl_domain(self):
        # 创建名为 "bl_domain" 的域名黑名单表
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS bl_domain (
                            this_domain TEXT PRIMARY KEY,
                            creat_time TEXT,
                            origin TEXT,
                            comment TEXT
                        )''')
        self.connection.commit()

    def bl_event(self):
        # 创建名为 "bl_event" 的CSP事件黑名单表
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS bl_event (
                            event TEXT PRIMARY KEY,
                            creat_time TEXT,
                            origin TEXT,
                            comment TEXT
                        )''')
        self.connection.commit()

    def eye_ip(self):
        # 创建名为 "eye_ip"的表。表示从VenusEye查询的IP
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS eye_ip (
                            ip TEXT PRIMARY KEY,
                            creat_time TEXT,
                            update_time TEXT,
                            threat_score INTEGER,
                            tags TEXT,
                            mal_ports TEXT,
                            ip_type TEXT,
                            categories TEXT,
                            families TEXT,
                            organizations TEXT,
                            country TEXT,
                            province TEXT,
                            city TEXT,
                            isp TEXT,
                            latitude TEXT,
                            longitude TEXT
        )''')
        self.connection.commit()

    def eye_domain(self):
        # 创建名为 "eye_domain"的表。表示从VenusEye查询的Domain
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS eye_domain (
                            this_domain TEXT PRIMARY KEY,
                            creat_time TEXT,
                            update_time TEXT,
                            threat_score INTEGER,
                            tags TEXT,
                            domain_main TEXT,
                            categories TEXT,
                            families TEXT,
                            organizations TEXT
        )''')
        self.connection.commit()

    def at_inner(self):
        # 创建名为 "at_inner" 的表。表示内网资产表
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS at_inner (
                            ip TEXT PRIMARY KEY,
                            belong TEXT,
                            creat_time TEXT,
                            comment TEXT
        )''')
        self.connection.commit()

    def at_outer(self):
        # 创建名为 "at_outer" 的表。表示业务暴露面IP资产表
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS at_outer (
                            ip TEXT PRIMARY KEY,
                            belong TEXT,
                            creat_time TEXT,
                            comment TEXT
        )''')
        self.connection.commit()

    def ban_ip(self):
        # 创建名为 "ban_ip"的表。表示封堵的IP表
        self.cursor_creat.execute('''CREATE TABLE IF NOT EXISTS ban_ip(
                            ip TEXT PRIMARY KEY,
                            creat_time TEXT,
                            reason TEXT,
                            ban_days INTEGER,
                            origin TEXT,
                            first_ban_time TEXT,
                            ban_count INTEGER,
                            ban_ip_address TEXT,
                            ip_relate_eventName TEXT,
                            comment TEXT,
                            comment1 TEXT
        )''')
        self.connection.commit()

    def CreatTables(self):
        self.wl_sip()
        self.wl_dip()
        self.wl_domain()
        self.wl_event()
        self.bl_sip()
        self.bl_dip()
        self.bl_domain()
        self.bl_event()
        self.eye_ip()
        self.eye_domain()
        self.at_outer()
        self.at_inner()
        self.ban_ip()
        self.cursor_creat.close()
        self.connection.close()
