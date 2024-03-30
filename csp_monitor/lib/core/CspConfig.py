from csp_monitor.lib.utils.convert import time_


class CSP:

    @staticmethod
    def status_url(ip) -> str:
        return "https://" + ip + "/api/system/monitor/deviceStatus/get"

    @staticmethod
    def page_url(ip) -> str:
        return "https://" + ip + "/api/eventLog/page"

    @staticmethod
    def detail_url(ip) -> str:
        return "https://" + ip + "/api/eventLog/detail"

    @staticmethod
    def count_url(ip):
        return "https://" + ip + "/api/eventLog/countThreatLevel"

    @staticmethod
    def param_of_log_count(beginTime, endTime) -> dict:
        return {"beginTime": time_(beginTime), "endTime": time_(endTime)}

    @staticmethod
    def param_of_onlyTotal(beginTime, endTime, **kwargs) -> dict:
        param_dict = {"flag": [], "gatherType": 0, "beginTime": time_(beginTime), "signatureLike": [], "desc": True,
                      "endTime": time_(endTime), "eventLogHotType": "HISTORY", "orderBy": "time_stamp",
                      "searchType": "onlyTotal", "pageNum": 1, "pageSize": 10, "threatLevel": [], "attackTactics": [],
                      "success": [], "category": [], "reverseAttackTactics": [], "reverseCategory": [],
                      "reverseSignatureLike": [], "reverseSuccess": [], "reverseThreatLevel": [], "threat": "",
                      "eventHost": "", "eventUrl": "", "eventXff": "", "eventXri": "", "attackLike": "", "proto": [],
                      "appProto": [], "httpMethod": [], "httpResponseCode": [], "srcDestDirection": [], "srcIp": [],
                      "destIp": [], "reverseSrcIp": [], "reverseDestIp": [], "srcPort": [], "destPort": [],
                      "reverseSrcPort": [], "reverseDestPort": [], "cloudThreatLevel": [], "cloudSearchType": [],
                      "exploitedHost": [], "offlineCategories": [], "offlineThreatLevel": [], "reverseEventUrl": "",
                      "reverseEventHost": "", "reverseEventXff": "", "reverseEventXri": "", "tunnelType": [],
                      "inInterface": [], "accuracy": [], "assetOnly": False, "meansOfAttack": [],
                      "reverseMeansOfAttack": [], "assetNameLike": [], "reverseAssetNameLike": []}
        [param_dict.update({k: v}) for k, v in kwargs.items() if k in param_dict.keys()]
        return param_dict

    @staticmethod
    def param_of_page(beginTime, endTime, pageNum, pageSize, **kwargs) -> dict:
        param_dict = {"flag": [], "gatherType": 0, "beginTime": time_(beginTime), "signatureLike": [], "desc": True,
                      "endTime": time_(endTime), "eventLogHotType": "HISTORY", "orderBy": "time_stamp",
                      "searchType": "onlyResult", "pageNum": pageNum, "pageSize": pageSize, "threatLevel": [],
                      "attackTactics": [],
                      "success": [], "category": [], "reverseAttackTactics": [], "reverseCategory": [],
                      "reverseSignatureLike": [], "reverseSuccess": [], "reverseThreatLevel": [], "threat": "",
                      "eventHost": "", "eventUrl": "", "eventXff": "", "eventXri": "", "attackLike": "", "proto": [],
                      "appProto": [], "httpMethod": [], "httpResponseCode": [], "srcDestDirection": [], "srcIp": [],
                      "destIp": [], "reverseSrcIp": [], "reverseDestIp": [], "srcPort": [], "destPort": [],
                      "reverseSrcPort": [], "reverseDestPort": [], "cloudThreatLevel": [], "cloudSearchType": [],
                      "exploitedHost": [], "offlineCategories": [], "offlineThreatLevel": [], "reverseEventUrl": "",
                      "reverseEventHost": "", "reverseEventXff": "", "reverseEventXri": "", "tunnelType": [],
                      "inInterface": [], "accuracy": [], "assetOnly": False, "meansOfAttack": [],
                      "reverseMeansOfAttack": [], "assetNameLike": [], "reverseAssetNameLike": []}
        [param_dict.update({k: v}) for k, v in kwargs.items() if k in param_dict.keys()]
        return param_dict

    @staticmethod
    def param_of_detail(logId: str, timestamp: int) -> dict:
        return {"id": logId, "timeStamp": timestamp}
