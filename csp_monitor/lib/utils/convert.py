import time
from datetime import datetime
import numpy as np


def default_dump(obj):
    """Convert numpy classes to JSON serializable objects.
    防止在numpy.int64 转换成int出错
    """
    if isinstance(obj, (np.integer, np.floating, np.bool_)):
        return obj.item()
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    else:
        return obj


def time_(A):
    """
    @description: 辅助方法，时间戳跟时间类型互转
    :param A: 处理服务器返回的字段中的时间字段
    :returns: 传入的是个unix时间戳则返回格式化后的时间，传入的是时间则返回时间戳
    """
    if isinstance(A, int):
        A = int(str(A)[0:10])
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(A))
    else:
        A = A[0:19]
        return int(time.mktime(time.strptime(A, "%Y-%m-%d %H:%M:%S")))


def time_ms(A):
    """精确到毫秒"""
    if isinstance(A, int):
        return datetime.fromtimestamp(A / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
    else:
        return int(datetime.strptime(A, "%Y-%m-%d %H:%M:%S").timestamp() * 1000)


def threatLevel_(level: int) -> str:
    """
    :param level: 20 代表低危，30 代表中危，40 代表高危，其他代表安全
    :return: 返回事件的等级（低-中-高危）
    """
    if level == 20:
        return '低危'
    elif level == 30:
        return '中危'
    elif level == 40:
        return '高危'
    else:
        return '安全'
