# QMCX CSP 运营分析之场景化监控

**感谢启明星辰威胁情报中心VenusEye提供威胁情报查询接口！**

Author：dearest

Organization:  OBG-运营商事业部-某部-某部-某部-安服仔

PS：没有CSP，就可以划走了......你打的流量能骗过设备，就可以不用看这篇文章了，你就是YYDS！

## What Can I Do ?

1. 设备在内网？没法出网？解决你设备无法出网实时获取IP/Domain威胁信息的问题。
2. 封IP嘎嘎快！封堵IP速度比你拿扫描器干还快，感兴趣可以试试。
3. 内网误报太多？策略不好写？哎，这都不是个事，有15个字段帮你设置策略。
4. 经测试，多台CSP一起分析，5分钟内能处理80W+的告警日志数据，一天处理500W+告警没压力。
5. 内网事件告警会对当天、近1月、近2月的日志进行环比分析。都梳理好发送到飞书，你可以不用24小时盯着设备来来回回点了。安服仔福音~
6. 封堵过的IP、封堵过的事件、没封堵的事件都存在EXCEL表格或数据库，给甲方ba ba汇报数据更方便了。
7. HW、重保啥的，只要CSP和部署这个程序的机子不被拿下，你就是传说中的**高级蓝队**哈哈哈

## What Do You Need To Prepare? 缺一不可

- Python3.9 +
- Redis 记得改端口跟设置密码（别被未授权拿下）
- Sqlite3
- Windows/Linux/Macos 都可以
- VenusEye Token 和 密钥
- 封IP的防火墙（没有就没法自动封IP）

## 上图



#### 程序运行截图

<img src="/Users/lipenghui/Library/Application Support/typora-user-images/image-20240330165120319.png" alt="image-20240330165120319" style="zoom:25%;" />

#### redis数据库的图

| 序号 | db   | 干啥的                                                       |
| ---- | ---- | ------------------------------------------------------------ |
| 1    | db0  | 存特征的，会把所有的事件特征，按天、按月进行存储，主要用于分析内网的误报 |
| 2    | db1  | 存误报策略的，15个字段供你选择，包含五元组字段               |

<img src="/Users/lipenghui/Library/Application Support/typora-user-images/image-20240330164448417.png" alt="image-20240330164448417" style="zoom:25%;" />

#### sqlite3数据库

| 序号 | 表名       | 干啥的                                                       |
| ---- | ---------- | ------------------------------------------------------------ |
| 1    | at_inner   | 内网IP资产对应表。有四个字段，是为了方便你找IP归属，溯源方便 |
| 2    | at_outer   | 外网IP资产对应表。跟at_inner作用一样                         |
| 3    | ban_ip     | 封堵过的IP表。有11个字段，方便甲方为了找事让你列出来封堵过哪些IP |
| 4    | bl_sip     | 源IP黑名单。顾名思义                                         |
| 5    | bl_dip     | 目的IP黑名单。顾名思义                                       |
| 6    | bl_domain  | 域名黑名单。顾名思义                                         |
| 7    | bl_event   | 事件名称黑名单，这个是CSP上的告警事件名称，触发就会发送告警到飞书 |
| 8    | eye_domain | VenusEye查询域名的结果                                       |
| 9    | eye_ip     | VenusEye查询IP的结果                                         |
| 10   | wl_sip     | 源IP白名单。顾名思义                                         |
| 11   | wl_dip     | 目的IP白名单。顾名思义                                       |
| 12   | wl_domain  | 域名白名单。顾名思义                                         |
| 13   | wl_event   | 事件名称白名单，自动过滤里面的所有事件。                     |

<img src="/Users/lipenghui/Library/Application Support/typora-user-images/image-20240330180628190.png" alt="image-20240330180628190" style="zoom:50%;" />

#### 飞书机器人发送的卡片消息

<img src="/Users/lipenghui/Library/Application Support/typora-user-images/image-20240330175724042.png" alt="image-20240330175724042" style="zoom:25%;" />

#### 程序实时生成的报表

<img src="/Users/lipenghui/Library/Application Support/typora-user-images/image-20240330180403301.png" alt="image-20240330180403301" style="zoom:50%;" />