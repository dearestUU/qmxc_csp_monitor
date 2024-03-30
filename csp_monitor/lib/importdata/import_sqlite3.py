# _*_ coding:utf-8 _*_


from concurrent.futures import ThreadPoolExecutor
from csp_monitor.lib.mysqlite3.OperationSqlite3 import sqlite
import pandas as pd
from csp_monitor.lib.utils.convert import time_ms

class Import:

    def __init__(self, filepath):
        self.filepath = filepath
        try:
            self.df = pd.DataFrame(data=pd.read_excel(self.filepath))
            self.count = self.df.shape[0]
        except Exception as ex1:
            print(f"文件路径不对! Error: {ex1}")

    def eye_domain(self):
        print(f"查询到 {self.count} 条数据,正在导入到数据库...")
        self.df.fillna('', inplace=True)
        tmp_value = []
        tmp_result = []
        for i in self.df.itertuples():
            try:
                this_domain = getattr(i,'this_domain')
                creat_time = getattr(i,'creat_time')
                update_time = getattr(i,'update_time')
                update_time = time_ms(A=update_time)
                threat_score = getattr(i,'threat_score')
                tags = getattr(i,'tags')
                domain_main = getattr(i,'domain_main')
                categories = getattr(i,'categories')
                families = getattr(i,'families')
                organizations = getattr(i,'organizations')
            except Exception as ex2:
                print(f"表格的字段和数据库字段不匹配不对! Error: {ex2}")
            else:
                value = (this_domain,creat_time,update_time,int(threat_score),tags,domain_main,categories,families,organizations)
                tmp_value.append(value)
        if len(tmp_value) > 0:
            with ThreadPoolExecutor(max_workers=50) as executor:
                future = [executor.submit(sqlite.insert, "eye_domain", value) for value in tmp_value]
                for f in future:
                    f_res = f.result()
                    if f_res == "FALSE":
                        tmp_result.append(1)

            print(f"共有{self.count}条数据，成功导入 eye_domain 数据库{int(self.count) - len(tmp_result)}条.")

    def at_inner(self):
        print(f"查询到 {self.count} 条数据,正在导入到数据库...")
        self.df.fillna('', inplace=True)
        tmp_value = []
        tmp_result = []
        for i in self.df.itertuples():
            try:
                ip = getattr(i,'ip')
                belong = getattr(i,'belong')
                creat_time = getattr(i,'creat_time')
                comment = getattr(i,'comment')
            except Exception as ex2:
                print(f"表格的字段和数据库字段不匹配不对! Error: {ex2}")
            else:
                value = (ip,belong,creat_time,comment)
                tmp_value.append(value)

        if len(tmp_value) > 0:
            with ThreadPoolExecutor(max_workers=50) as executor:
                future = [executor.submit(sqlite.insert, "at_inner", value) for value in tmp_value]
                for f in future:
                    f_res = f.result()
                    if f_res == "FALSE":
                        tmp_result.append(1)

            print(f"共有{self.count}条数据，成功导入 at_inner 数据库{int(self.count) - len(tmp_result)}条.")

    def eye_ip(self):
        print(f"查询到 {self.count} 条数据,正在导入到数据库...")
        self.df.fillna('', inplace=True)

        tmp_value = []
        tmp_result = []

        for i in self.df.itertuples():
            try:
                ip = getattr(i,'ip')
                creat_time = getattr(i,'creat_time')
                update_time = getattr(i, 'update_time')
                update_time = time_ms(A=update_time)
                threat_score = int(getattr(i,'threat_score'))
                tags = getattr(i,'tags')
                mal_ports = getattr(i,'mal_ports')
                ip_type = getattr(i,'ip_type')
                categories = getattr(i,'categories')
                families = getattr(i,'families')
                organizations = getattr(i,'organizations')
                country = getattr(i,'country')
                province = getattr(i,'province')
                city = getattr(i,'city')
                isp = getattr(i,'isp')
                latitude = getattr(i,'latitude')
                longitude = getattr(i,'longitude')
            except Exception as ex2:
                print(f"表格的字段和数据库字段不匹配不对! Error: {ex2}")
            else:
                value = (ip,creat_time,update_time,int(threat_score),str(tags),str(mal_ports),str(ip_type),str(categories),str(families),str(organizations),str(country),str(province),str(city),str(isp),str(latitude),str(longitude))
                tmp_value.append(value)

        if len(tmp_value) > 0:
            with ThreadPoolExecutor(max_workers=50) as executor:
                future = [executor.submit(sqlite.insert, "eye_ip", value) for value in tmp_value]
                for f in future:
                    f_res = f.result()
                    if f_res == "FALSE":
                        tmp_result.append(1)

            print(f"共有{self.count}条数据，成功导入 eye_ip 数据库{int(self.count) - len(tmp_result)}条.")

