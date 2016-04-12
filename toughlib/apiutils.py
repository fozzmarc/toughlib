#!/usr/bin/env python
# coding:utf-8 
import time
import json
from hashlib import md5
from toughlib import utils, httpclient


def make_sign(api_secret, params=[]):
    """
        >>> make_sign("123456",[1,'2',u'中文'])
        '33C9065427EECA3490C5642C99165145'
    """
    _params = [utils.safeunicode(p) for p in params if p is not None]
    _params.sort()
    _params.insert(0, api_secret)
    strs = ''.join(_params)
    mds = md5(strs.encode('utf-8')).hexdigest()
    return mds.upper()

def c_make_sign(params={}):
    """
        >>> c_make_sign({"k1":"v1", "k2":"v2"})
        '33C9065427EECA3490C5642C99165145'
    """
    _params = [utils.safeunicode(k) for k in params if k is not None]
    _params.sort()
    _params2 = [utils.safeunicode(k)+'='+params[k]+'&' for k in _params if k is not None]
    strs = ''.join(_params2).strip('&')
    mds = md5(strs.encode('utf-8')).hexdigest()
    return mds.lower()

def check_sign(api_secret, msg):
    """
        自定义加密串
        >>> check_sign("123456",dict(code=1,s='2',msg=u'中文',sign='33C9065427EECA3490C5642C99165145'))
        True

    """
    if "sign" not in msg:
        return False
    sign = msg['sign']
    params = [utils.safestr(msg[k]) for k in msg if k != 'sign']
    local_sign = make_sign(api_secret, params)
    return sign == local_sign

def c_check_sign(msg):
    """
        自定义加密
        >>> c_check_sign(dict(code=1,s='2',msg=u'中文',sign='33C9065427EECA3490C5642C99165145'))
        True
    """
    if "sign" not in msg:
        return False
    sign = msg.pop('sign')
    local_sign = c_make_sign(msg)
    return sign == local_sign

def make_message(api_secret, enc_func=False, **params):
    """
        >>> json.loads(make_request("123456",**dict(code=1,msg=u"中文",nonce=1451122677)))['sign']
        u'58BAF40309BC1DC51D2E2DC43ECCC1A1'
    """
    if 'nonce' not in params:
        params['nonce' ] = str(int(time.time()))
    params['sign'] = make_sign(api_secret, params.values())
    msg = json.dumps(params, ensure_ascii=False)
    if callable(enc_func):
        return enc_func(msg)
    else:
        return msg

def make_error(api_secret, msg=None, enc_func=False):
    return make_message(api_secret,code=1,msg=msg, enc_func=enc_func)

def parse_request(api_secret, reqbody, dec_func=False):
    """
        >>> parse_request("123456",'{"nonce": 1451122677, "msg": "helllo", "code": 0, "sign": "DB30F4D1112C20DFA736F65458F89C64"}')
        {u'nonce': 1451122677, u'msg': u'helllo', u'code': 0, u'sign': u'DB30F4D1112C20DFA736F65458F89C64'}
    """
    try:
        if callable(dec_func):
            req_msg = json.loads(dec_func(reqbody))
        else:
            req_msg = json.loads(reqbody)
    except Exception as err:
        raise ValueError(u"parse params error")

    if not check_sign(api_secret, req_msg):
        raise ValueError(u"message sign error")

    return req_msg

def c_parse_request(reqbody, dec_func=False):
    """
        没有token进行加密 - 适用于卡平台的特殊加密
        >>> c_parse_request('{"nonce": 1451122677, "msg": "helllo", "code": 0, "sign": "DB30F4D1112C20DFA736F65458F89C64"}')
        {u'nonce': 1451122677, u'msg': u'helllo', u'code': 0, u'sign': u'DB30F4D1112C20DFA736F65458F89C64'}
    """
    try:
        if callable(dec_func):
            req_msg = json.loads(dec_func(reqbody))
        else:
            req_msg = json.loads(reqbody)
    except Exception as err:
        raise ValueError(u"parse params error")
    
    if not c_check_sign(req_msg):
        raise ValueError(u"message sign error")
        
    return req_msg

def request(apiurl, data=None, **kwargs):
    headers = {"Content-Type": ["application/json"]}
    return httpclient.post(apiurl, data=data, **kwargs)

if __name__ == "__main__":
    import doctest
    doctest.testmod()

    
