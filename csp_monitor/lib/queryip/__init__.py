# _*_ coding:utf-8 _*_

"""
-------------------------------------------------
@Author: dearest
@Data: 2024/1/20 03:29
@File: __init__.py.py
@Version: 1.0.0
@Description: TODO
@Question: NO
-------------------------------------------------
"""
import ipaddress

def is_valid_domain(domain):
    tmp_str = domain.replace('-', '').replace('.', '')
    special_chars = "!@#$%^&*()+?_=,<>/:{}_|;'[]"
    for char in tmp_str:
        if char in special_chars:
            return False
    if ipv4_or_ipv6(ip=domain) != 'not_ip':
        return False
    else:
        return True

def is_valid_ip(ip: str) -> bool:
    """
    :param ip:
    :return: 判断是不是一个IP
    """
    try:
        ipaddress.ip_address(ip).version == 4 or ipaddress.ip_address(ip).version == 6
        return True
    except Exception:
        # logger_r.error(f"`{ip}` is not ipv4 or ipv6")
        return False

def ipv4_or_ipv6(ip: str):
    """
    :param ip:
    :return: 判断是ipv4还是ipv6.返回 ipv4  ipv6  not_ip
    """
    if is_valid_ip(ip=ip):
        if ipaddress.ip_address(ip).version == 4:
            return "ipv4"
        else:
            return "ipv6"
    else:
        return "not_ip"
