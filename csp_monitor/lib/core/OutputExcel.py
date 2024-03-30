import pandas as pd
import os
from csp_monitor import logger, logger_r


class ToExcel:

    SUCCESS = 1
    FAILED = 0

    def __init__(self, columns: list, data, path: str):
        self.columns = columns
        self.data = data
        self.path = path
        self.xlsxName = os.path.basename(path)
        self.xlsxPath = os.path.dirname(path)

    @property
    def output(self):
        try:
            if self.xlsxName not in os.listdir(self.xlsxPath):
                # 如果文件名不在路径下
                df = pd.DataFrame(data=self.data, columns=self.columns)
                if 'timeStamp' in self.columns:
                    df.sort_values(by='timeStamp',inplace=True)

                with pd.ExcelWriter(path=self.path, engine='openpyxl') as write:
                    df.to_excel(write, index=False)
            else:
                df1 = pd.DataFrame(data=self.data, columns=self.columns)
                df2 = pd.read_excel(self.path, engine='openpyxl', sheet_name=0)
                df = pd.concat([df1, df2], axis=0)  # 先合并，在写入

                if 'timeStamp' in self.columns:
                    df.sort_values(by='timeStamp',inplace=True)

                with pd.ExcelWriter(path=self.path, engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
                    df.to_excel(excel_writer=writer, index=False, sheet_name='Sheet1')
        except Exception as ex:
            errMsg = f">>> {self.path} 表格写入有问题: {ex}"
            logger_r.info(errMsg)
            logger.info(errMsg)
            return ToExcel.FAILED
        else:
            return ToExcel.SUCCESS
