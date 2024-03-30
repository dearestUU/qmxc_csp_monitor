# _*_ coding:utf-8 _*_

import time

def execute_time(func):
    def wrapper(*args, **kwargs):
        sTime = time.time()
        result = func(*args, **kwargs)
        eTime = time.time()
        print(f">>> {func.__name__} 执行耗时 {round(eTime - sTime, 2)} 秒")
        return result

    return wrapper


