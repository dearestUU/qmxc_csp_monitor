# _*_ coding:utf-8 _*_

import os.path
import sys
import time
from datetime import datetime, timedelta
import pandas as pd
import paramiko
from pandas import DataFrame
from csp_monitor import logger
from csp_monitor.lib.core.OutputExcel import ToExcel
from csp_monitor.lib.core.decorator import execute_time
from csp_monitor.lib.core.setting import HAVE_BAN_EVENT_PATH, HAVE_BAN_IP_PATH, UNBAN_IPV6_PATH, UNBAN_EVENT_PATH, creat_folder, NOT_IP_PATH, IP_NOT_RECORD_IN_DB, TRUE_ALARM, FALSE_ALARM, BLACK_IP_EVENT, SQLITE3_PATH
from csp_monitor.setting import FIREWALL_HOST,FIREWALL_PORT,FIREWALL_USER,FIREWALL_PASS, FIREWALL_PATH_1,FIREWALL_PATH_2
from csp_monitor.lib.core.AnalysisCspResult import Analysis
from csp_monitor.lib.policy.policy0 import P0
from csp_monitor.lib.policy.policy1 import P1
from csp_monitor.lib.policy.policy2 import P2
from csp_monitor.lib.policy.policy3 import P3
from csp_monitor.lib.policy.policy4 import P4
from csp_monitor.lib.policy.policy5 import P5
from csp_monitor.lib.policy.policy6 import P6
from csp_monitor.lib.queryip.ban_ip import BAN
from csp_monitor.lib.sendmsg.feishu import Feishu
from csp_monitor.lib.mysqlite3.CreatTables import CT

columns = ['devIp', 'srcIp', 'destIp', 'signature', 'threatLevel', 'timeStamp', 'srcPort', 'destPort', "eventUrl", "eventHost", "eventXff", 'eventXri', 'appProto', 'proto', 'count', 'sip_add', 'dip_add', "result", 'comment']

func1_columns = ["devIp", "srcIp", "destIp","sip_add", "dip_add", "signature", "threatLevel", "timeStr","srcPort", "destPort", "eventUrl","eventHost","eventXff", "eventXri", "appProto", "proto", "count", "result", "timeStr_day", "devIp_day", "signature_day", "count_day", "timeStr_one_month", "devIp_one_month", "signature_one_month", "count_one_month", "timeStr_two_month", "devIp_two_month", "signature_two_month","count_two_month"]

func6_columns = ['devIp', 'srcIp', 'destIp', 'signature', 'threatLevel', 'timeStamp', 'srcPort', 'destPort', "eventUrl", "eventHost", "eventXff", 'eventXri', 'appProto', 'proto', 'count', 'sip_add', 'dip_add', "result", 'comment']


def main(sTime, eTime, **kwargs):
    result = Analysis.sip_dip(sTime=sTime, eTime=eTime, **kwargs)
    # print(result)
    if isinstance(result, list):
        return []
    else:
        if 0 in result:
            var0 = result[0]
            func0(df=var0)
        if 1 in result:
            var1 = result[1]
            func1(df=var1)
        if 2 in result:
            var2 = result[2]
            func2(df=var2)
        if 3 in result:
            var3 = result[3]
            func3(df=var3)
        if 4 in result:
            var4 = result[4]
            func4(df=var4)
        if 5 in result:
            var5 = result[5]
            func5(df=var5)
        if 6 in result:
            var6 = result[6]
            func6(df=var6)

@execute_time
def func0(df: DataFrame):

    res = P0.policy(df=df)
    BAN_IP = res[0]
    UNBAN_IP = res[-1]

    if len(BAN_IP) > 0:
        df1 = pd.DataFrame(data=BAN_IP, columns=columns)

        df_filtered_sip = df1[df1['comment'].str.contains("源IP")][['srcIp','signature','sip_add','comment']].values.tolist()
        df_filtered_dip = df1[df1['comment'].str.contains("目的IP")][['destIp','signature','dip_add','comment']].values.tolist()

        subset = df_filtered_sip + df_filtered_dip
        tmp_df_ban = pd.DataFrame(subset)
        tmp_df_ban.drop_duplicates(subset=0,inplace=True)
        subset = tmp_df_ban.values.tolist()

        to_firewall(data=subset)  # 上传到防火墙
        
        is_record_in_db = is_in_have_ban_db(data=subset)
        if is_record_in_db is None:
            pass
        else:
            judge_is_save_in_db(df1=df1,data=is_record_in_db)


    """
    3、记录封堵数据到 HAVE_BAN_EVENT_PATH的表格
    """
    if len(BAN_IP) > 0:
        to_xlsx(dataList=BAN_IP, path=HAVE_BAN_EVENT_PATH)

    """
    4、记录未封堵数据到 表格
    """
    if len(UNBAN_IP) > 0:
        to_xlsx(dataList=UNBAN_IP, path=UNBAN_IPV6_PATH)

@execute_time
def func1(df: DataFrame):
    res = P1.policy(df=df)
    shi_wu_bao = res[0]
    fei_wu_bao = res[-1]

    if len(fei_wu_bao) > 0:
        tmp_si_di = pd.DataFrame(data=fei_wu_bao)
        tmp_si_di.drop_duplicates(subset=[1,2],inplace=True)
        tmp_si_di = tmp_si_di.values.tolist()
        for v in tmp_si_di:
            fs_content = [v[1],v[3],v[2],v[4],v[18],v[19],v[20],v[21],v[22],v[23],v[24],v[25],v[26],v[27],v[28],v[29],v[7],v[0]]
            Feishu().new_green_card(fs_content)

    if len(shi_wu_bao) > 0:
        to_xlsx(dataList=shi_wu_bao, path=FALSE_ALARM)

    if len(fei_wu_bao) > 0:
        to_xlsx(dataList=fei_wu_bao, path=TRUE_ALARM)

@execute_time
def func2(df: DataFrame):

    res = P2.policy(df=df)
    BAN_DATA = res[0]
    UNBAN_DATA = res[-1]

    if len(BAN_DATA) > 0:
        df1 = pd.DataFrame(data=BAN_DATA, columns=columns)
        subset = df1[['srcIp','signature','sip_add','comment']].values.tolist()

        tmp_df_ban = pd.DataFrame(subset)
        tmp_df_ban.drop_duplicates(subset=0,inplace=True)
        subset = tmp_df_ban.values.tolist()

        to_firewall(data=subset)  # 上传到防火墙
        is_record_in_db = is_in_have_ban_db(data=subset)
        if is_record_in_db is None:
            pass
        else:
            judge_is_save_in_db(df1=df1,data=is_record_in_db)

    if len(BAN_DATA) > 0:
        to_xlsx(dataList=BAN_DATA,path=HAVE_BAN_EVENT_PATH)

    if len(UNBAN_DATA) > 0:
        to_xlsx(dataList=UNBAN_DATA,path=UNBAN_EVENT_PATH)

@execute_time
def func3(df: DataFrame):
    res = P3.policy(df=df)
    BAN_SIP = res[0]
    BAN_DIP = res[1]
    UNBAN_SIP = res[2]
    UNBAN_DIP = res[3]
    UNBAN = res[4]

    BAN_DATA = []
    UNBAN_DATA_LIST = UNBAN_SIP + UNBAN_DIP + UNBAN
    BAN_DATA_LIST = BAN_SIP + BAN_DIP

    if len(BAN_SIP) > 0:
        df1 = pd.DataFrame(data=BAN_SIP)
        subset1 = df1.iloc[:, [1, 3, 15, 18]]
        BAN_DATA += subset1.values.tolist()

    if len(BAN_DIP) > 0:
        df2 = pd.DataFrame(data=BAN_DIP)
        subset2 = df2.iloc[:, [2, 3, 16, 18]]
        BAN_DATA += subset2.values.tolist()

    if len(BAN_DATA) > 0:

        tmp_df_ban = pd.DataFrame(BAN_DATA)
        tmp_df_ban.drop_duplicates(subset=0,inplace=True)
        BAN_DATA = tmp_df_ban.values.tolist()

        to_firewall(data=BAN_DATA)  # 上传到防火墙
        is_record_in_db = is_in_have_ban_db(data=BAN_DATA)
        if is_record_in_db is None:
            pass
        else:
            df3 = pd.DataFrame(data=BAN_DATA_LIST, columns=columns)
            judge_is_save_in_db(df1=df3, data=is_record_in_db)


    if len(BAN_DATA_LIST) > 0:
        to_xlsx(dataList=BAN_DATA_LIST,path=HAVE_BAN_EVENT_PATH)

    if len(UNBAN_DATA_LIST) > 0:
        to_xlsx(dataList=UNBAN_DATA_LIST,path=UNBAN_EVENT_PATH)

@execute_time
def func4(df: DataFrame):
    res = P4.policy(df=df)
    BAN_DATA = res[0]
    UNBAN_DATA = res[-1]

    if len(BAN_DATA) > 0:
        df1 = pd.DataFrame(data=BAN_DATA, columns=columns)
        subset = df1[['destIp','signature','dip_add','comment']].values.tolist()

        tmp_df_ban = pd.DataFrame(data=subset)
        tmp_df_ban.drop_duplicates(subset=0,inplace=True)
        subset = tmp_df_ban.values.tolist()

        to_firewall(data=subset)
        is_record_in_db = is_in_have_ban_db(data=subset)
        if is_record_in_db is None:
            pass
        else:
            judge_is_save_in_db(df1=df1,data=is_record_in_db)

    if len(BAN_DATA) > 0:
        to_xlsx(dataList=BAN_DATA,path=HAVE_BAN_EVENT_PATH)

    if len(UNBAN_DATA) > 0:
        to_xlsx(dataList=UNBAN_DATA,path=UNBAN_EVENT_PATH)

@execute_time
def func5(df: DataFrame):
    res = P5.policy(df=df)
    if len(res) > 0:
        to_xlsx(dataList=res,path=NOT_IP_PATH)

@execute_time
def func6(df: DataFrame):
    res = P6.policy(df=df)
    if len(res) > 0:

        to_xlsx(dataList=res, path=BLACK_IP_EVENT)

        for v in res:
            fs_content = [v[0],v[1],v[2],v[3],v[4],v[5],v[15],v[16],v[17],v[18]]
            Feishu().new_red_card(fs_content)

def judge_is_save_in_db(df1: DataFrame, data: list):
    try:
        df2 = pd.DataFrame(data=data,columns=['ip', 'reason'])
        df3 = df2[df2['reason'].str.contains("源IP")]
        if df3.shape[0] > 0:
            subset1 = df1[~df1['srcIp'].isin(df3['ip'].values.tolist())].values.tolist()
            to_xlsx(dataList=subset1, path=IP_NOT_RECORD_IN_DB)

        df4 = df2[df2['reason'].str.contains("目的IP")]
        if df4.shape[0] > 0:
            subset2 = df1[~df1['destIp'].isin(df4['ip'].values.tolist())].values.tolist()
            to_xlsx(dataList=subset2, path=IP_NOT_RECORD_IN_DB)
    except Exception as e:
        print(e)

def is_in_have_ban_db(data: list):
    df = pd.DataFrame(data,columns=['ip', 'eventName', 'ip_address', 'ban_reason'])
    df.drop_duplicates(inplace=True,keep='first',subset='ip')
    nowTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ip_not_record_in_db = []
    for i in df.itertuples():
        ip = getattr(i, 'ip')
        eventName = getattr(i,'eventName')
        ban_ip_address = getattr(i, 'ip_address')
        ban_reason = getattr(i,'ban_reason')
        ban_result = BAN.BanIp(ip=ip,creat_time=nowTime,reason=ban_reason,ban_days=0,ban_ip_address=ban_ip_address, eventName=eventName)
        if ban_result is True:
            pass
        else:
            ip_not_record_in_db.append([ip, ban_reason])

    if len(ip_not_record_in_db) == 0:
        return None
    else:
        return ip_not_record_in_db


def to_firewall(data: list):
    df = pd.DataFrame(data=data,columns=['ip', 'eventName', 'ip_address', ''])
    df.drop_duplicates(inplace=True,keep='first',subset='ip')

    nowTime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logName = f"monitor{nowTime[:16].replace(' ', '').replace(':', '').replace('-', '')}_{int(time.time() * 100000)}.log"
    logPath = os.path.join(HAVE_BAN_IP_PATH, logName)
    uploadIp = []
    for var in df.itertuples():
        ip = getattr(var,'ip')  # 封堵的IP
        eventName = getattr(var,'eventName')
        ban_ip_address = getattr(var,'ip_address')
        uploadIp.append(ip)
        content = f"{nowTime};{ip};{eventName};{ban_ip_address}"
        with open(logPath, 'a', encoding='utf-8') as f:
            f.write(f'{content}\n')
    try:
        if logName in os.listdir(HAVE_BAN_IP_PATH):
            transport = paramiko.Transport((FIREWALL_HOST, FIREWALL_PORT))
            transport.connect(username=FIREWALL_USER, password=FIREWALL_PASS)
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.put(logPath, FIREWALL_PATH_1 + logName)
            sftp.put(logPath, FIREWALL_PATH_2 + logName)
            transport.close()
    except Exception as e:
        errMsg2 = f">>> 0x10 == 连接防火墙出问题了！！ 原因: {e}"
        logger.error(errMsg2)
        Feishu().error(message=errMsg2)
    else:
        if len(uploadIp) > 0:
            upload_ip_to_feishu = '\n'.join(uploadIp)
            Feishu().text_wai(f"{logName} 已上传至防火墙.如下:\n{upload_ip_to_feishu}")
            logger.info(f'{logName} 已上传至服务器!')
        else:
            print("当前监控频率没有待封堵的IP")

def to_xlsx(dataList,path):
    if path == UNBAN_EVENT_PATH:
        xlsxPath = os.path.join(UNBAN_EVENT_PATH,f"unban_{datetime.now().strftime('%Y_%m_%d')}.xlsx")
        res1 = ToExcel(columns=columns, data=dataList, path=xlsxPath).output
    elif path == HAVE_BAN_EVENT_PATH:
        xlsxPath = os.path.join(HAVE_BAN_EVENT_PATH,f"have_ban_{datetime.now().strftime('%Y_%m_%d')}.xlsx")
        res2 = ToExcel(columns=columns, data=dataList, path=xlsxPath).output
    elif path == UNBAN_IPV6_PATH:
        xlsxPath = os.path.join(UNBAN_IPV6_PATH,f"ipv6_{datetime.now().strftime('%Y_%m_%d')}.xlsx")
        res3 = ToExcel(columns=columns, data=dataList, path=xlsxPath).output
    elif path == NOT_IP_PATH:
        xlsxPath = os.path.join(NOT_IP_PATH,f"si_do_{datetime.now().strftime('%Y_%m_%d')}.xlsx")
        res4 = ToExcel(columns=columns, data=dataList, path=xlsxPath).output
    elif path == TRUE_ALARM:
        xlsxPath = os.path.join(TRUE_ALARM,f"true_alarm_{datetime.now().strftime('%Y_%m_%d')}.xlsx")
        res5 = ToExcel(columns=func1_columns, data=dataList, path=xlsxPath).output
    elif path == FALSE_ALARM:
        xlsxPath = os.path.join(FALSE_ALARM,f"false_alarm_{datetime.now().strftime('%Y_%m_%d')}.xlsx")
        res6 = ToExcel(columns=func1_columns, data=dataList, path=xlsxPath).output
    elif path == BLACK_IP_EVENT:
        xlsxPath = os.path.join(BLACK_IP_EVENT, f"blacklist_{datetime.now().strftime('%Y_%m_%d')}.xlsx")
        res6 = ToExcel(columns=func6_columns, data=dataList, path=xlsxPath).output


global delay_time
if __name__ == '__main__':

    try:
        CT().CreatTables()
        assert os.path.exists(SQLITE3_PATH)
    except AssertionError:
        print('`csp_monitor`目录下未发现assert.db, 程序已退出 !!!')
        sys.exit()
    else:
        logger.info(">>> asset.db 存在! <<<")

    try:
        creat_folder()
    except FileExistsError as fileExistsError:
        print(f'目录创建失败, 程序已退出 !!! 原因如下: {fileExistsError}')
        sys.exit()

    delay_time = 0
    while True:
        time1 = time.time()
        ssTime = (datetime.now() - timedelta(minutes=7, seconds=delay_time)).strftime('%Y-%m-%d %H:%M:%S')
        eeTime = (datetime.now() - timedelta(minutes=2)).strftime('%Y-%m-%d %H:%M:%S')

        sss = (datetime.strptime(eeTime, "%Y-%m-%d %H:%M:%S") - datetime.strptime(ssTime, "%Y-%m-%d %H:%M:%S")).seconds
        logger.info("-" * 89)
        logger.info(f"S/{ssTime}{' ' * 5}E/{eeTime}")
        logger.info("-" * 89)

        main(sTime=ssTime, eTime=eeTime)

        time2 = time.time()
        interval = 300 - (time2 - time1)
        if interval > 0:
            logger.info(f"{'-' * 89}")
            logger.info(f">>> 本轮监控频率耗时{int(time2 - time1)}秒. 监控中,本轮监控时间段为{sss}秒,{int(interval)}秒后继续...")
            time.sleep(interval)
            delay_time = 0
        else:
            delay_time = abs(interval)

