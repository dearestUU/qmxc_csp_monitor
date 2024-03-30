# _*_ coding:utf-8 _*_

"""
-------------------------------------------------
@Author: dearest
@Data: 2024/1/22 01:22
@File: time_differ.py
@Version: 1.0.0
@Description: TODO
@Question: NO
-------------------------------------------------
"""

from datetime import datetime

def same_day(sTime: datetime, eTime: datetime) -> bool:
    """
    :param sTime:
    :param eTime:
    :return: 判断两个时间在同一天
    """
    if sTime.date() == eTime.date():
        return True
    else:
        return False


def same_month(sTime: datetime, eTime: datetime) -> bool:
    """
    :param sTime:
    :param eTime:
    :return: 判断两个时间在同一月
    """
    if sTime.year == eTime.year and sTime.month == eTime.month:
        return True
    else:
        return False


def same_year(sTime: datetime, eTime: datetime) -> bool:
    """
    :param sTime:
    :param eTime:
    :return: 判断两个时间在同一月
    """
    if sTime.year == eTime.year:
        return True
    else:
        return False
