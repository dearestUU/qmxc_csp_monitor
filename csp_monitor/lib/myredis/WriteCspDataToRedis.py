# _*_ coding:utf-8 _*_

import json
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
from csp_monitor import logger_r
from csp_monitor.lib.myredis.ConnectRedis import RC
from csp_monitor.lib.utils.convert import default_dump


class WTR:
    name = "write to redis 的缩写"

    @staticmethod
    def save_rules(devIp: list = ["*"], srcIp: str = "*", destIp: str = "*", eventName: str = "*", firstTimeStamp: str = "*", lastTimeStamp: str = "*", srcPort: list = ["*"], destPort: list = ["*"], eventUrl: list = ["*"], eventHost: list = ["*"],eventXff: list = ["*"], eventXri: list = ["*"], appProto: list = ["*"], proto: list = ["*"], count: int = 0, comment1: str = "", comment2: str = ""):
        """
        :param devIp: 设备IP ，必须时list，默认为 ["*"]
        :param srcIp: 源IP，默认为 "*"
        :param destIp: 目的IP，默认为 "*"
        :param eventName: 事件名称，默认为 "*"
        :param firstTimeStamp: 事件第一次发生时间，默认为 "*"
        :param lastTimeStamp: 事件最后一次发生事件，默认为 "*"
        :param srcPort: 源端口，默认为 ["*"]
        :param destPort: 目的端口，默认为 ["*"]
        :param eventUrl: 事件URL，默认为 ["*"]
        :param eventHost: Host字段，默认为 ["*"]
        :param eventXff: XFF字段，默认为 ["*"]
        :param eventXri: XRI字段，默认为 ["*"]
        :param appProto: 应用协议，默认为 ["*"]
        :param proto: 协议，默认为 ["*"]
        :param count: 次数，默认为0
        :param comment1:
        :param comment2:
        :return:
        """
        if srcIp == "*" and destIp == "*" and eventName == "*":
            print("源IP、目的IP、事件名称，不能都为'*' ！")
        else:
            connection = RC.redis_connect_db1()
            set_name = f"{srcIp}_{destIp}_{eventName}"
            if connection.exists(set_name) == 1:
                print("该规则已存在!")
            else:
                content = {
                    "devIp": devIp,
                    "srcIp": srcIp,
                    "destIp": destIp,
                    "signature": eventName,
                    "firstTimeStamp": firstTimeStamp,
                    "lastTimeStamp": lastTimeStamp,
                    "srcPort": srcPort,
                    "destPort": destPort,
                    "eventUrl": eventUrl,
                    "eventHost": eventHost,
                    "eventXff": eventXff,
                    "eventXri": eventXri,
                    "appProto": appProto,
                    "proto": proto,
                    "count": count,
                    "comment1": comment1,
                    "comment2": comment2
                }
                content = json.dumps(content, ensure_ascii=False)
                try:
                    connection.set(set_name, content)
                except Exception as e:
                    print(f"规则写入redis的db1数据库时出错啦!!! reason: {e}")

    @staticmethod
    def save_to_redis(result, connection, conn_db: int, set_name, sTime, eTime, set_day: int):
        try:

            if isinstance(result, dict):
                flag_1 = [connection.hset(name=set_name, key=key, value=json.dumps(value, ensure_ascii=False, default=default_dump)) for key, value in result.items()]

                if len(result) == sum(flag_1):
                    pass
                else:
                    logger_r.info(
                        f"redis>>> db={conn_db} name={set_name} day={set_day} 有{len(result) - sum(flag_1)}失败.")

                if set_day > 0:
                    connection.expire(set_name, set_day * 60 * 60 * 24)
            else:
                logger_r.info(f">>> {sTime} - {eTime} 时间段内无数据.")
        except Exception as ex:
            logger_r.error(msg=f">>> {sTime} - {eTime} 写入redis的db0出错!具体原因: {ex}")

    @staticmethod
    def update_to_redis(result:dict, connection, conn_db: int, set_name):
        if connection.exists(set_name) == 1:
            hash_data = connection.hgetall(name=set_name)
            with ThreadPoolExecutor(max_workers=100) as executor:
                [executor.submit(WTR._ready_update, connection, hash_data, set_name, key1, result, conn_db) for key1 in result.keys()]
        else:
            logger_r.error(msg=f"{set_name} 该表不存在.")

    @staticmethod
    def _ready_update(connection, hash_data, name, key1,new_data, conn_db:int):
        if key1.encode('utf-8') in hash_data.keys():
            value_in_name = json.loads(connection.hget(name=name, key=key1).decode())
            value_in_new_data = new_data[key1]
            json_str = []
            [json_str.append({kk: vv}) for kk, vv in value_in_name.items()]
            [json_str.append({kk: vv}) for kk, vv in value_in_new_data.items()]

            result = WTR._merge_data(json_str=json_str)
            flag = connection.hset(name=name, key=key1,value=json.dumps(result, ensure_ascii=False,default=default_dump))
            if flag == 0:
                pass
            else:
                logger_r.error(f'redis>>> {key1} 已在 {name} 合并更新数据失败.')
        else:
            flag = connection.hset(name=name,key=key1, value=json.dumps(new_data[key1], ensure_ascii=False, default=default_dump))
            if flag == 1:
                pass
            else:
                logger_r.error(f"redis>>> {key1} 已在 {name} 更新失败.")

    @staticmethod
    def _merge_data(json_str) -> dict:
        result = {}
        for var in json_str:
            for k1, v1 in var.items():
                if k1 not in result:
                    result[k1] = {"signature": [], "threatLevel": [], "srcPort": "","destPort":"", "eventUrl":[],"eventXff":'',"eventXri":"","appProto":"","proto":"","timeStamp":[],"count":0}
                result[k1]["signature"] = list(set(result[k1]["signature"] + v1["signature"]))
                result[k1]["threatLevel"] = list(set(result[k1]["threatLevel"] + v1["threatLevel"]))
                result[k1]['eventUrl'] = list(set(result[k1]["eventUrl"] + v1["eventUrl"]))
                result[k1]['timeStamp'] = pd.Series(list(set(result[k1]["timeStamp"] + v1["timeStamp"]))).sort_values().iloc[[0,-1]].tolist()
                result[k1]['count'] = sum([result[k1]['count'], v1["count"]])

                # 写在一行不易阅读代码，所以分行写：srcPort
                if result[k1]['srcPort'] == '' and v1['srcPort'] == '':
                    result[k1]['srcPort'] = ''
                elif result[k1]['srcPort'] == '' and v1['srcPort'] != '':
                    if '*' in str(v1['srcPort']):
                        result[k1]['srcPort'] = '*'
                    else:
                        result[k1]['srcPort'] = ','.join(list(set(v1['srcPort'].replace(' ','').split(','))))
                elif result[k1]['srcPort'] != '' and v1['srcPort'] != '':
                    if '*' in result[k1]['srcPort']:
                        result[k1]['srcPort'] = '*'
                    elif '*' in v1['srcPort']:
                        result[k1]['srcPort'] = '*'
                    else:
                        result[k1]['srcPort'] = ','.join(list(set(result[k1]['srcPort'].split(',') + v1['srcPort'].split(','))))
                else:
                    result[k1]['srcPort'] = result[k1]['srcPort']

                if result[k1]['destPort'] == '' and v1['destPort'] == '':
                    result[k1]['destPort'] = ''
                elif result[k1]['destPort'] == '' and v1['destPort'] != '':
                    if '*' in str(v1['destPort']):
                        result[k1]['destPort'] = '*'
                    else:
                        result[k1]['destPort'] = ','.join(list(set(v1['destPort'].replace(' ','').split(','))))
                elif result[k1]['destPort'] != '' and v1['destPort'] != '':
                    if '*' in result[k1]['destPort']:
                        result[k1]['destPort'] = '*'
                    elif '*' in v1['destPort']:
                        result[k1]['destPort'] = '*'
                    else:
                        result[k1]['destPort'] = ','.join(list(set(result[k1]['destPort'].split(',') + v1['destPort'].split(','))))
                else:
                    result[k1]['destPort'] = result[k1]['destPort']

                # 写在一行不易阅读代码，所以分行写：eventXff
                if result[k1]['eventXff'] == '' and v1['eventXff'] == '':
                    result[k1]['eventXff'] = ''
                elif result[k1]['eventXff'] == '' and v1['eventXff'] != '':
                    result[k1]['eventXff'] = ','.join(list(set(v1['eventXff'].replace(' ','').split(','))))
                elif result[k1]['eventXff'] != '' and v1['eventXff'] != '':
                    result[k1]['eventXff'] = ','.join(list(set(result[k1]['eventXff'].split(',') + v1['eventXff'].split(','))))
                else:
                    result[k1]['eventXff'] = result[k1]['eventXff']

                # 写在一行不易阅读代码，所以分行写：eventXri
                if result[k1]['eventXri'] == '' and v1['eventXri'] == '':
                    result[k1]['eventXri'] = ''
                elif result[k1]['eventXri'] == '' and v1['eventXri'] != '':
                    result[k1]['eventXri'] = ','.join(list(set(v1['eventXri'].replace(' ','').split(','))))
                elif result[k1]['eventXri'] != '' and v1['eventXri'] != '':
                    result[k1]['eventXri'] = ','.join(list(set(result[k1]['eventXri'].split(',') + v1['eventXri'].split(','))))
                else:
                    result[k1]['eventXri'] = result[k1]['eventXri']

                # 写在一行不易阅读代码，所以分行写：appProto
                if result[k1]['appProto'] == '' and v1['appProto'] == '':
                    result[k1]['appProto'] = ''
                elif result[k1]['appProto'] == '' and v1['appProto'] != '':
                    result[k1]['appProto'] = ','.join(list(set(v1['appProto'].replace(' ','').split(','))))
                elif result[k1]['appProto'] != '' and v1['appProto'] != '':
                    result[k1]['appProto'] = ','.join(list(set(result[k1]['appProto'].split(',') + v1['appProto'].split(','))))
                else:
                    result[k1]['appProto'] = result[k1]['appProto']

                # 写在一行不易阅读代码，所以分行写：proto
                if result[k1]['proto'] == '' and v1['proto'] == '':
                    result[k1]['proto'] = ''
                elif result[k1]['proto'] == '' and v1['proto'] != '':
                    result[k1]['proto'] = ','.join(list(set(v1['proto'].replace(' ','').split(','))))
                elif result[k1]['proto'] != '' and v1['proto'] != '':
                    result[k1]['proto'] = ','.join(list(set(result[k1]['proto'].split(',') + v1['proto'].split(','))))
                else:
                    result[k1]['proto'] = result[k1]['proto']
        return result
