# _*_ coding:utf-8 _*_

from csp_monitor.lib.queryip import is_valid_ip, is_valid_domain, ipv4_or_ipv6
from csp_monitor.lib.queryip.query_ip import Q_IP
from csp_monitor.lib.queryip.query_domain import Q_DOMAIN

def ip_or_domain(field: str, timeStamp: int = None, eventName: str = None):

    if is_valid_ip(ip=field) is True:
        return Q_IP.query_ip(ip=field,ts=timeStamp,en=eventName)[2]
    elif is_valid_domain(domain=field) is True:
        return Q_DOMAIN.query_domain(domain=field,ts=timeStamp,en=eventName)[2]
    else:
        return "not_ip_or_domain"
