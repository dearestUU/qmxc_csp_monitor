# _*_ coding:utf-8 _*_


import redis
from csp_monitor.setting import redis_host, redis_port, redis_password


def is_redis_alive() -> bool:
    r = redis.Redis(host=redis_host, port=redis_port, db=2)
    try:
        r.ping()
        return True
    except:
        return False

class RedisSingleton:
    _name = "redis 连接的单例模式"
    _instances = {}

    def __new__(cls, db_index):
        if db_index not in cls._instances:
            cls._instances[db_index] = super(RedisSingleton, cls).__new__(cls)
            cls._instances[db_index]._redis = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password, db=db_index)
        return cls._instances[db_index]

    def get_redis_connection(self):
        return self._redis


class RC:
    name = "连接redis"

    @staticmethod
    def redis_connect_db0():
        return RedisSingleton(0).get_redis_connection()

    @staticmethod
    def redis_connect_db0_pool():
        pool = redis.ConnectionPool(host=redis_host, port=redis_port, password=redis_password, db=0, decode_responses=True, max_connections=50)
        return redis.Redis(connection_pool=pool)

    @staticmethod
    def redis_connect_db1():
        pool = redis.ConnectionPool(host=redis_host, port=redis_port, password=redis_password, db=1, decode_responses=True, max_connections=50)
        return redis.Redis(connection_pool=pool)

    @staticmethod
    def redis_connect_db2():
        return RedisSingleton(2).get_redis_connection()

