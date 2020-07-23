from urllib.parse import quote as urlencode
from urllib.parse import unquote as urldecode
from base64 import b64encode as base64encode
from base64 import b64decode as base64decode
from copy import deepcopy
import json
import sys
import random
import string


class generate_payload_class:
    def __init__(self, params, param_type, payload='', check_keys=[], mode='cover'):
        # init
        self.params = params  # 输入要添加payload的param
        self.param_type = param_type  # 设置param的类型，为json或params两种
        self.payload = payload  # 设置payload
        self.check_keys = check_keys  # 指定对某个key进行操作，使用in进行判断
        self.mode = mode  # 判断是否为cover，如果不是cover则在原参数值的基础上添加payload
        self.json_params = {}  # 存储json格式中的dict类型
        self.list_params = {}  # 存储json格式中的list类型
        self.save_types = {}  # 存储url中每一个参数对应的编码类型，后续拼接payload时解码会用到
        self.key_to_payload_tmp = {}  # 存储每一个param对应的payload
        self.extract_results = {}  # 存储结果

        if self.param_type == 'params':
            """将a=1&b=2的形式转换为字典存储"""
            split_params = self.params.split('&')
            for param in split_params:
                if '=' in param:
                    k = param.split('=')[0]
                    v = param.split('=')[1]
                    self.json_params[k] = v
                    encode_types = self.get_encode_types(v)
                    decode_v = self.decode(v, encode_types)
                    try:
                        json_load_v = json.loads(decode_v)
                        if isinstance(json_load_v, dict) or isinstance(json_load_v, list):
                            pass
                        else:
                            json_load_v = None
                    except:

                        json_load_v = None
                        pass
                    if json_load_v is None:
                        self.json_params[k] = decode_v
                        self.save_types[k] = encode_types
                    else:
                        self.json_params[k] = json_load_v
                        encode_types.append('json')
                        self.save_types[k] = encode_types
        elif self.param_type == 'json':
            """判断json是list还是dict"""
            try:
                json_load = json.loads(self.params)
            except:
                print('[-]Can\'t not load json.')
                sys.exit()
            if isinstance(json_load, dict):
                for k in json_load:
                    value = json_load[k]
                    encode_types = self.get_encode_types(value)
                    decode_value = self.decode(value, encode_types)
                    try:
                        load_json = json.loads(decode_value)
                        if isinstance(load_json, dict) or isinstance(load_json, list):
                            encode_types.append('json')
                    except:
                        load_json = decode_value
                        pass
                    self.json_params[k] = load_json
                    self.save_types[k] = encode_types
            elif isinstance(json_load, list):
                self.param_type = 'list'
                self.list_params = json_load

    def encode(self, value, encode_types):
        """根据encode_types对字符串进行编码"""
        if encode_types is []:
            return value
        encode_types = list(reversed(encode_types))
        for encode_type in encode_types:
            if encode_type == 'json':
                value = json.dumps(value)
            if encode_type == 'base64encode':
                value = str(base64encode(value.encode('utf-8')), encoding='utf-8')
            if encode_type == 'urlencode':
                value = urlencode(value)
        return value

    def decode(self, value, encode_types):
        """根据encode_types对字符串进行解码"""
        for encode_type in encode_types:
            if encode_type == 'urlencode':
                value = urldecode(value)
            if encode_type == 'base64encode':
                value = str(base64decode(value.encode('utf-8')), encoding='utf-8')
        return value

    def get_encode_types(self, value):
        value = str(value)
        encode_types = []
        if value == '':
            return encode_types
        """判断是否存在urlencode"""
        try:
            url_decode_value = urldecode(value)
        except:
            return False
        if url_decode_value != value:
            encode_types.append('urlencode')

        """判断是否为int或者float，避免后面的base64判断出错"""
        try:
            json_load_value = json.loads(url_decode_value)
            if isinstance(json_load_value, int) or isinstance(json_load_value, float):
                return encode_types
        except:
            pass

        """调用base64decode，判断返回字符串是否在可见范围内"""
        try:
            base64decode_value = base64decode(url_decode_value.encode('utf-8'))
            string_basedecode = base64decode_value.decode()
            for _ in string_basedecode:
                if 32 <= ord(_) <= 126:
                    continue
                else:
                    return encode_types
        except:
            return encode_types

        """判断是否为base64加密"""
        try:
            if str(base64encode(base64decode_value), encoding='utf-8') == url_decode_value:
                encode_types.append("base64encode")
        except:
            return encode_types

        return encode_types

    def generate_payload(self):
        """生成payload"""
        if self.param_type == 'json' or self.param_type == 'params':
            for k in self.json_params:
                payload = self.payload
                if '{random_str}' in payload:
                    payload = payload.format(random_str=self.get_random_str(6))
                origin_value = self.json_params[k]
                if isinstance(origin_value, dict):
                    self.add_payload_in_list_dict_string(k, payload, origin_value)
                    self.add_payload_json(origin_value, deep_key=k)
                elif isinstance(origin_value, list):
                    self.add_payload_in_list_dict_string(k, payload, origin_value)
                    self.add_payload_list(origin_value, deep_key=k)
                elif isinstance(origin_value, str):
                    encode_types = self.save_types[k]
                    if self.mode == 'cover':
                        encode_payload = self.encode(payload, encode_types)
                        self.key_to_payload_tmp[k] = payload
                    else:
                        encode_payload = self.encode(origin_value + payload, encode_types)
                        self.key_to_payload_tmp[k] = origin_value + payload

                    self.json_params[k] = encode_payload
                    if self.check_keys:
                        if not self.is_in_check_key(k):
                            continue
                    self.extract_results[k] = deepcopy(self.json_params)
                    self.json_params[k] = origin_value
        elif self.param_type == 'list':
            self.add_payload_list(self.list_params)

        return self.extract_result()

    def add_payload_json(self, json_value, deep_key=''):
        """对json进行处理"""
        for k in json_value.keys():
            origin_value = json_value[k]
            payload = self.payload
            if '{random_str}' in payload:
                payload = payload.format(random_str=self.get_random_str(6))
            if isinstance(origin_value, dict):
                if deep_key != '':
                    self.add_payload_in_list_dict_string(k, payload, origin_value, json_paramer=json_value,
                                                         real_key=deep_key + '.' + k)
                    self.add_payload_json(origin_value, deep_key + '.' + k)
                else:
                    self.add_payload_in_list_dict_string(k, payload, origin_value, json_paramer=json_value,
                                                         real_key=k)
                    self.add_payload_json(origin_value, k)
            elif isinstance(origin_value, list):
                if deep_key != '':
                    self.add_payload_in_list_dict_string(k, payload, origin_value, json_paramer=json_value,
                                                         real_key=deep_key + '.' + k)
                    self.add_payload_list(origin_value, deep_key + '.' + k)
                else:
                    self.add_payload_in_list_dict_string(k, payload, origin_value, json_paramer=json_value,
                                                         real_key=k)
                    self.add_payload_list(origin_value, k)
            else:
                str_value = str(origin_value)  # 避免出现int、float、boolean的情况
                encode_types = self.get_encode_types(origin_value)

                if self.mode == 'cover':
                    if deep_key != '':
                        self.key_to_payload_tmp[deep_key + '.' + k] = payload
                    else:
                        self.key_to_payload_tmp[k] = payload
                    encode_payload = self.encode(payload, encode_types)
                    json_value[k] = encode_payload
                else:
                    if deep_key != '':
                        self.key_to_payload_tmp[deep_key + '.' + k] = str_value + payload
                    else:
                        self.key_to_payload_tmp[k] = str_value + payload
                    encode_payload = self.encode(str_value + payload, encode_types)
                    json_value[k] = encode_payload
                if self.check_keys:
                    if not self.is_in_check_key(k):
                        continue
                if self.param_type == 'params' or self.param_type == 'json':
                    if deep_key != '':
                        self.extract_results[deep_key + '.' + k] = deepcopy(self.json_params)
                    else:
                        self.extract_results[k] = deepcopy(self.json_params)
                elif self.param_type == 'list':
                    if deep_key != '':
                        self.extract_results[deep_key + '.' + k] = deepcopy(self.list_params)
                    else:
                        self.extract_results[k] = deepcopy(self.list_params)
                json_value[k] = origin_value

    def add_payload_list(self, list_value, deep_key=''):
        """对list进行处理"""
        i = 0
        for value in list_value:
            payload = self.payload
            if '{random_str}' in payload:
                payload = payload.format(random_str=self.get_random_str(6))
            if isinstance(value, dict):
                if deep_key == '':
                    self.add_payload_json(value, str(i))
                else:
                    self.add_payload_json(value, deep_key=deep_key + '.' + str(i))
            elif isinstance(value, list):
                if deep_key == '':
                    self.add_payload_list(value, str(i))
                else:
                    self.add_payload_list(value, deep_key=deep_key + '.' + str(i))
            else:
                list_value[i] = payload
                encode_types = self.get_encode_types(str(value))
                encode_payload = self.encode(payload, encode_types)
                if deep_key == '':
                    self.key_to_payload_tmp[str(i)] = payload
                else:
                    self.key_to_payload_tmp[deep_key + '.' + str(i)] = payload

                if self.mode == 'cover':
                    list_value[i] = encode_payload
                else:
                    list_value[i] = str(value) + encode_payload
                if self.check_keys:
                    if not self.is_in_check_key(deep_key):
                        continue
                if self.param_type == 'params' or self.param_type == 'json':
                    if deep_key == '':
                        self.extract_results[str(i)] = deepcopy(self.json_params)
                    else:
                        self.extract_results[deep_key + '.' + str(i)] = deepcopy(self.json_params)
                elif self.param_type == 'list':
                    if deep_key == '':
                        self.extract_results[str(i)] = deepcopy(self.list_params)
                    else:
                        self.extract_results[deep_key + '.' + str(i)] = deepcopy(self.list_params)
                list_value[i] = value

            i += 1

    def get_random_str(self, len_str):
        """获取随机字符串"""
        salt = ''.join(random.sample(string.ascii_letters, len_str))
        return salt

    def is_in_check_key(self, key):
        """判断当前key是否在check list中"""
        for check_key in self.check_keys:
            if key in check_key:
                return True
        return False

    def extract_result(self):
        """解析结果"""
        payloads = {}
        if self.param_type == 'params':
            for k, v in self.extract_results.items():
                full_params = ''
                for param_k, param_v in v.items():
                    encode_types = self.save_types[param_k]
                    encode_param_v = self.encode(param_v, encode_types)
                    full_params += param_k + '=' + encode_param_v + '&'
                full_params = full_params[:-1]
                payloads[k] = full_params
        elif self.param_type == 'json' or self.param_type == 'list':
            for k in self.extract_results.keys():
                payloads[k] = json.dumps(self.extract_results[k])

        return self.key_to_payload_tmp, payloads

    def add_payload_in_list_dict_string(self, k, payload, origin_value, json_paramer={}, real_key=''):
        """对json、list等单独添加payload"""
        if json_paramer == {}:
            self.json_params[k] = payload
        else:
            json_paramer[k] = payload
        if real_key == '':
            self.key_to_payload_tmp[k] = payload
            if self.check_keys:
                if not self.is_in_check_key(k):
                    return False
            if self.param_type == 'json' or self.param_type == 'params':
                self.extract_results[k] = deepcopy(self.json_params)
            elif self.param_type == 'list':
                self.extract_results[k] = deepcopy(self.list_params)
        else:
            self.key_to_payload_tmp[real_key] = payload
            if self.param_type == 'json' or self.param_type == 'params':
                self.extract_results[real_key] = deepcopy(self.json_params)
            elif self.param_type == 'list':
                self.extract_results[real_key] = deepcopy(self.list_params)
        if json_paramer == {}:
            self.json_params[k] = origin_value
        else:
            json_paramer[k] = origin_value


if __name__ == '__main__':
    test_param1 = 'k1=v1&k2={"k3":1,"k4":[1,2,"YXNkYXNk"]}'
    test_param2 = 'k1=v1&k2=%7b%22subject%22%3a%22rwawr%22%2c%22description%22%3a%7b%22detail%22%3a%22%3cp%3etest%3c%2fp%3e%22%2c%22value%22%3a%22test%22%7d%2c%22project%22%3a%221%22%2c%22priority%22%3a%225%22%2c%22url%22%3a%22rwar%22%2c%22assignee%22%3a%22%22%2c%22caller%22%3a%22op-admin%22%2c%22issue_id%22%3a7795301%7d'
    test_param3 = '[1,2,3]'
    test_param4 = r'{"ev_type":"batch","list":[{"ev_type":"pageview","version":"3.4.33","hostname":"www.toutiao.com","protocol":"https","url":"https://www.toutiao.com/","slardar_session_id":"71613a9c-19ce-475f-bad8-ccfe3bf0c2bc","sample_rate":1,"pid":"index_new","report_domain":"i.snssdk.com","screen_resolution":"1536x864","network_type":"4g","bid":"toutiao_pc","context":"{}","slardar_web_id":"3136dc1f-04de-4026-a082-efe11b436e44","report_type":"xhr","performanceAuto":true,"reportURLSingle":"https://i.snssdk.com/log/sentry/v2/api/slardar/main/","region":"cn","hookPath":true,"hookXHR":true,"hookFetch":true,"enableSizeStats":true,"enableFMP":true,"enablePerformance":true,"enableStaticError":true,"enableCatchJSError":true,"enableCrash":true,"enableMemoryRecord":true,"enableFPSJankTimesMonitor":true,"enableBreadcrumb":true,"hookConsole":false},{"ev_type":"ajax","ax_status":"200","ax_type":"post","ax_request_header":"Accept: application/json\r\nContent-Type: application/json;charset=UTF-8","ax_domain":"verify.snssdk.com","ax_duration":310,"ax_path":"/reportError","ax_protocol":"https","ax_response_header":"access-control-allow-credentials: true\r\naccess-control-allow-origin: *\r\naccess-control-expose-headers: *\r\nconnection: close\r\ncontent-length: 35\r\ncontent-type: text/html; charset=utf-8\r\ndate: Wed, 22 Jul 2020 12:18:44 GMT\r\nserver: nginx/1.14.2\r\nserver-timing: inner; dur=0\r\nx-tt-logid: 202007222018440100190261330E0A4014\r\nx-tt-timestamp: 1595420324.389\r\nx-tt-trace-host: 014e44f6dfbd542ff9c61a42d2689b39feac1ff7c050f2b2adeb4cda67631778ee370cb9a1522bd8a36353be232485a6fc9a569534fb1243641734d125f3461141\r\nx-tt-trace-tag: id=00;cdn-cache=miss","ax_size":35,"ax_url":"https://verify.snssdk.com/reportError","version":"3.4.33","hostname":"www.toutiao.com","protocol":"https","url":"https://www.toutiao.com/","slardar_session_id":"71613a9c-19ce-475f-bad8-ccfe3bf0c2bc","sample_rate":1,"pid":"index_new","report_domain":"i.snssdk.com","screen_resolution":"1536x864","network_type":"4g","bid":"toutiao_pc","context":"{}","slardar_web_id":"3136dc1f-04de-4026-a082-efe11b436e44","report_type":"xhr","performanceAuto":true,"reportURLSingle":"https://i.snssdk.com/log/sentry/v2/api/slardar/main/","region":"cn","hookPath":true,"hookXHR":true,"hookFetch":true,"enableSizeStats":true,"enableFMP":true,"enablePerformance":true,"enableStaticError":true,"enableCatchJSError":true,"enableCrash":true,"enableMemoryRecord":true,"enableFPSJankTimesMonitor":true,"enableBreadcrumb":true,"hookConsole":false},{"ev_type":"ajax","ax_status":"200","ax_type":"post","ax_request_header":"X-MCS-AppKey: 566f58151b0ed37e","ax_domain":"mcs.snssdk.com","ax_duration":308,"ax_path":"/v1/list","ax_protocol":"https","ax_response_header":"cache-control: no-store, no-cache, must-revalidate\r\ncontent-length: 7\r\ncontent-type: application/json; charset=utf-8\r\nexpires: 0\r\npragma: no-cache","ax_size":7,"ax_url":"https://mcs.snssdk.com/v1/list","version":"3.4.33","hostname":"www.toutiao.com","protocol":"https","url":"https://www.toutiao.com/","slardar_session_id":"71613a9c-19ce-475f-bad8-ccfe3bf0c2bc","sample_rate":1,"pid":"index_new","report_domain":"i.snssdk.com","screen_resolution":"1536x864","network_type":"4g","bid":"toutiao_pc","context":"{}","slardar_web_id":"3136dc1f-04de-4026-a082-efe11b436e44","report_type":"xhr","performanceAuto":true,"reportURLSingle":"https://i.snssdk.com/log/sentry/v2/api/slardar/main/","region":"cn","hookPath":true,"hookXHR":true,"hookFetch":true,"enableSizeStats":true,"enableFMP":true,"enablePerformance":true,"enableStaticError":true,"enableCatchJSError":true,"enableCrash":true,"enableMemoryRecord":true,"enableFPSJankTimesMonitor":true,"enableBreadcrumb":true,"hookConsole":false},{"ev_type":"ajax","ax_status":"200","ax_type":"post","ax_request_header":"Content-Type: application/json; charset=utf-8","ax_domain":"mcs.snssdk.com","ax_duration":324,"ax_path":"/v1/list","ax_protocol":"https","ax_response_header":"cache-control: no-store, no-cache, must-revalidate\r\ncontent-length: 7\r\ncontent-type: application/json; charset=utf-8\r\nexpires: 0\r\npragma: no-cache","ax_size":7,"ax_url":"https://mcs.snssdk.com/v1/list","version":"3.4.33","hostname":"www.toutiao.com","protocol":"https","url":"https://www.toutiao.com/","slardar_session_id":"71613a9c-19ce-475f-bad8-ccfe3bf0c2bc","sample_rate":1,"pid":"index_new","report_domain":"i.snssdk.com","screen_resolution":"1536x864","network_type":"4g","bid":"toutiao_pc","context":"{}","slardar_web_id":"3136dc1f-04de-4026-a082-efe11b436e44","report_type":"xhr","performanceAuto":true,"reportURLSingle":"https://i.snssdk.com/log/sentry/v2/api/slardar/main/","region":"cn","hookPath":true,"hookXHR":true,"hookFetch":true,"enableSizeStats":true,"enableFMP":true,"enablePerformance":true,"enableStaticError":true,"enableCatchJSError":true,"enableCrash":true,"enableMemoryRecord":true,"enableFPSJankTimesMonitor":true,"enableBreadcrumb":true,"hookConsole":false},{"ev_type":"ajax","ax_status":"200","ax_type":"get","ax_request_header":"","ax_domain":"s3a.pstatp.com","ax_duration":205,"ax_path":"/growth/slardar/sdk/plugins/browser/worker.3.4.33.cn.js","ax_protocol":"https","ax_response_header":"cache-control: max-age=36288000\r\ncontent-length: 1649\r\ncontent-type: application/javascript\r\nexpires: Fri, 10 Sep 2021 11:30:45 GMT\r\nlast-modified: Fri, 17 Jul 2020 11:08:05 GMT","ax_size":1649,"ax_url":"https://s3a.pstatp.com/growth/slardar/sdk/plugins/browser/worker.3.4.33.cn.js","version":"3.4.33","hostname":"www.toutiao.com","protocol":"https","url":"https://www.toutiao.com/","slardar_session_id":"71613a9c-19ce-475f-bad8-ccfe3bf0c2bc","sample_rate":1,"pid":"index_new","report_domain":"i.snssdk.com","screen_resolution":"1536x864","network_type":"4g","bid":"toutiao_pc","context":"{}","slardar_web_id":"3136dc1f-04de-4026-a082-efe11b436e44","report_type":"xhr","performanceAuto":true,"reportURLSingle":"https://i.snssdk.com/log/sentry/v2/api/slardar/main/","region":"cn","hookPath":true,"hookXHR":true,"hookFetch":true,"enableSizeStats":true,"enableFMP":true,"enablePerformance":true,"enableStaticError":true,"enableCatchJSError":true,"enableCrash":true,"enableMemoryRecord":true,"enableFPSJankTimesMonitor":true,"enableBreadcrumb":true,"hookConsole":false}],"timestamp":1595420324440}'
    test_param5 = r'[{"events":[{"event":"pageview","params":"{\"from\":\"index\",\"utm_source\":\"\",\"event_index\":1595420414364}","local_time_ms":1595420322990}],"user":{"user_unique_id":"6842079684584064520","web_id":"6842079684584064520","ssid":"4362355b-cff3-4819-a9bc-a744b776c79a"},"header":{"headers":"{\"custom\":{\"screen_width\":1536,\"screen_height\":864}}","os_name":"windows","os_version":"10","device_model":"windows","language":"zh-CN","platform":"web","sdk_version":"3.2.14","timezone":8,"tz_offset":-28800,"resolution":"1536x864","browser":"Chrome","browser_version":"84.0.4147.89","referrer":"","referrer_host":"www.toutiao.com","app_id":2256}}]'
    test_param6 = r'{"events":[{"type":"exposure_duration","cnt":59.998,"url":"https://star.toutiao.com/ad#/recharge"}],"token":"7ebcc8c11883d0412de1c5afd9c9fd363e12308b","language":"zh_CN","user":{"user_id":"1672899101391886","user_name":"mock用户","web_id":"0f0793ad-d8d1-4687-95a2-031d4c7ab30b"},"params":{"url":"https://star.toutiao.com/ad#/recharge"}}'
    test_param7 = r'{"ev_type":"batch","list":[{"ev_type":"ajax","ax_status":"200","ax_type":"get","ax_request_header":"Accept: application/json, text/plain, */*\r\nx-star-service-name: generic.AdStarGenericService\r\nx-star-service-method: IMTotalUnread\r\nX-CSRFToken: 6L4l6PV9A9DiGe46NqvAd1AUJ5nJ6bYh","ax_duration":118,"ax_size":51,"ax_response_header":"connection: close\r\ncontent-length: 51\r\ncontent-type: application/json;charset=utf-8\r\ndate: Wed, 22 Jul 2020 08:05:16 GMT\r\neagleid: 670f631c15954051165014967e\r\nserver: Tengine\r\nserver-timing: inner; dur=36\r\ntiming-allow-origin: *\r\nupstream-caught: 1595405116507921\r\nvary: Accept-Encoding, Cookie\r\nvia: cache8.cn844[44,0]\r\nx-frame-options: SAMEORIGIN\r\nx-tt-timestamp: 1595405116.543\r\nx-tt-trace-host: 01ea5df697d1e40974594cff72249629da5bf5dc193cd508ba1ce779fec47db6fb2711d05d36a87341c1912f9f0e03bb2c65989293e9bb5fe5c23a51723edc01e98fbf91741afec6d88e195833bde4ef58\r\nx-tt-trace-tag: id=3;cdn-cache=miss\r\nx_tt_logid: 20200722160516010014016095190CE0B0","ax_protocol":"https","ax_domain":"star.toutiao.com","ax_path":"/h/api/gateway/handler_get/generic.AdStarGenericService/IMTotalUnread","ax_url":"https://star.toutiao.com/h/api/gateway/handler_get/","version":"2.1.36","hostname":"star.toutiao.com","protocol":"https","url":"https://star.toutiao.com/ad#/recharge","slardar_session_id":"324aa591-dc50-46ac-ab81-8be8c8640120","sample_rate":1,"pid":"/ad","report_domain":"i.snssdk.com","screen_resolution":"1536x864","network_type":"4g","bid":"ad_star_fe","context":"{\"username\":\"crazylocust\"}","slardar_web_id":"1672899101391886","report_type":"beacon","performanceAuto":true,"domestic":true,"reportURLSingle":"https://i.snssdk.com/log/sentry/v2/api/slardar/main/"}]}'
    test_param8 = '{"k1":"v1","k2":{"k3":"v2"},"k4":[1,2,3]}'
    test_param9 = 'id=qweqweqweqasdqwe'
    print(generate_payload_class(test_param9, 'params', '<payload>').generate_payload())
