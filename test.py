# -*- coding: utf-8 -*-
"""
@author: obaby
@license: (C) Copyright 2013-2020, obaby@mars.
@contact: root@obaby.org.cn
@link: http://www.obaby.org.cn
        http://www.h4ck.org.cn
        http://www.findu.co
@file: fulao.py
@time: 2020/6/28 16:04
@desc:
"""
from Crypto.Cipher import AES
import hashlib
import requests
import base64
import random
import json
import time
import urllib.parse


def aes_decrypt(key, data, ivs):
    data = data.encode('utf8')
    encodebytes = base64.decodebytes(data)
    cipher = AES.new(key, AES.MODE_CBC, ivs)
    text_decrypted = cipher.decrypt(encodebytes)
    unpad = lambda s: s[0:-s[-1]]
    text_decrypted = unpad(text_decrypted)
    # 去补位
    text_decrypted = text_decrypted.decode('utf8')
    return text_decrypted


def md5(str):
    m = hashlib.md5()
    m.update(str.encode(encoding='utf-8'))
    return m.hexdigest()


def aes_decrypt_raw(key, data, ivs):
    encodebytes = data
    cipher = AES.new(key, AES.MODE_CBC, ivs)
    text_decrypted = cipher.decrypt(encodebytes)
    unpad = lambda s: s[0:-s[-1]]
    text_decrypted = unpad(text_decrypted)
    # 去补位
    # text_decrypted = text_decrypted.decode('utf8')
    return text_decrypted


def aes_encrypt(key, data, vi):
    pad = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
    data = pad(data)
    # 字符串补位
    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, vi.encode('utf8'))
    encryptedbytes = cipher.encrypt(data.encode('utf8'))
    # 加密后得到的是bytes类型的数据
    encodestrs = base64.b64encode(encryptedbytes)
    #
    enctext = encodestrs.decode('utf8')
    # 对byte字符串按utf-8进行解码
    return enctext


def aes_encrypt_raw(key, data, vi):
    pad = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
    data = pad(data)
    # 字符串补位
    cipher = AES.new(key, AES.MODE_CBC, vi)
    encryptedbytes = cipher.encrypt(data.encode('utf8'))
    # 加密后得到的是bytes类型的数据
    encodestrs = base64.b64encode(encryptedbytes)
    #
    enctext = encodestrs.decode('utf8')
    # 对byte字符串按utf-8进行解码
    return enctext


def decode_image():
    f = open(r"H:\PyCharmProjects\frida_test\avid5c33013611e90.jpg", 'rb')
    b = f.read()
    f.close()
    # array@7687 (type=[B)
    image_key_base64 = bytes('svOEKGb5WD0ezmHE4FXCVQ==', encoding='utf8')  # 图片解密key
    image_key = base64.decodebytes(image_key_base64)
    print(image_key)
    iv = base64.decodebytes(bytes('4B7eYzHTevzHvgVZfWVNIg==', encoding='utf8'))  # 图片解密iv
    de = aes_decrypt_raw(image_key, b, iv)
    f = open(r"H:\PyCharmProjects\frida_test\avid5c33013611e90_decode.jpg", 'wb')
    f.write(de)
    f.close()


def request_payload_decrypt(source_string):
    unquote_string = urllib.parse.unquote(source_string)
    data_list = unquote_string.split('.')
    key = base64.decodebytes(bytes('euZN1Gg3JIwWOEWhmE7C4l5dSSRU34fyuPMXjtuoqVs=', encoding='utf8'))
    iv = base64.decodebytes(bytes(data_list[0], encoding='utf8'))
    source_data = data_list[1]

    decrypt_string = aes_decrypt(key, source_data, iv)
    print("DECRYPT_STRING:", decrypt_string)


def new_video_get_test():
    request_key = base64.decodebytes(bytes('euZN1Gg3JIwWOEWhmE7C4l5dSSRU34fyuPMXjtuoqVs=', encoding='utf8'))
    request_iv = b'\x49\x09\x3E\x49\x6D\x29\x50\xBB\xF1\x67\x9C\x5D\x52\x77\xBF\x4E'
    request_iv = base64.decodebytes(bytes('HTpKwS4MVfB2pktFSGRzvw==', encoding='utf8'))

    ss = '{"timestamp":"' + str(int(
        time.time())) + '","order":"time","video_type":"long","type":"uncover","page":"1","token":"eyJ1c2VyX2lkIjoyMTg4MjU2NCwibGFzdGxvZ2luIjoxNTkzMzI3NzQyfQ.c39375da9af6cf24aae0349c4f0b5641.9b0e72bc9a1eea26114dc955d730603e4c11f865d43ea9595d9fd29c","path":"v1/videos/menu/0"}'

    ds = aes_encrypt_raw(request_key, ss, request_iv)
    print(ds)
    payload = 'HTpKwS4MVfB2pktFSGRzvw==.' + ds
    base_url = 'https://api-tc.bjsongmoxuan.cn/v1/videos/menu/0?payload=' + urllib.parse.quote(payload)

    print(base_url)
    resp = requests.get(base_url)
    print(resp.text)

    # 1216557403 x-vtag
    response_headers = resp.headers
    vtag = response_headers.get('x-vtag')
    print(vtag)

    i = md5(vtag)
    print(i)
    iv = i[8:24]
    print(iv)
    new_key = md5('fe34dd6bbd3020c2fb69abe73b5b973c')
    dds = aes_decrypt(new_key.encode('utf8'),
                      resp.text,
                      iv.encode('utf8'))
    print(dds)


def new_video_get_recommand_test(video_id):
    request_key = base64.decodebytes(bytes('euZN1Gg3JIwWOEWhmE7C4l5dSSRU34fyuPMXjtuoqVs=', encoding='utf8'))
    request_iv = b'\x49\x09\x3E\x49\x6D\x29\x50\xBB\xF1\x67\x9C\x5D\x52\x77\xBF\x4E'
    request_iv = base64.decodebytes(bytes('HTpKwS4MVfB2pktFSGRzvw==', encoding='utf8'))

    ss = '{"timestamp":"' + str(int(
        time.time())) + '","page":"1","token":"eyJ1c2VyX2lkIjoyMTg4MjU2NCwibGFzdGxvZ2luIjoxNTkzMzI3NzQyfQ.c39375da9af6cf24aae0349c4f0b5641.9b0e72bc9a1eea26114dc955d730603e4c11f865d43ea9595d9fd29c","path":"v1/videos/recommend/' + video_id + '"}'

    ds = aes_encrypt_raw(request_key, ss, request_iv)
    print(ds)
    payload = 'HTpKwS4MVfB2pktFSGRzvw==.' + ds
    base_url = 'https://api.bdxxo.cn/v1/videos/recommend/' + video_id + '?payload=' + urllib.parse.quote(payload)

    print(base_url)
    resp = requests.get(base_url)
    print(resp.text)

    # 1216557403 x-vtag
    response_headers = resp.headers
    vtag = response_headers.get('x-vtag')
    print(vtag)

    i = md5(vtag)
    print(i)
    iv = i[8:24]
    print(iv)
    new_key = md5('fe34dd6bbd3020c2fb69abe73b5b973c')
    dds = aes_decrypt(new_key.encode('utf8'),
                      resp.text,
                      iv.encode('utf8'))
    print(dds)


def new_video_get_detail_test(video_id):
    request_key = base64.decodebytes(bytes('euZN1Gg3JIwWOEWhmE7C4l5dSSRU34fyuPMXjtuoqVs=', encoding='utf8'))
    request_iv = b'\x49\x09\x3E\x49\x6D\x29\x50\xBB\xF1\x67\x9C\x5D\x52\x77\xBF\x4E'
    request_iv = base64.decodebytes(bytes('HTpKwS4MVfB2pktFSGRzvw==', encoding='utf8'))

    # {"an_stream":"https://tv-as.00ph.cn","timestamp":"1593568332","an_quality":"240","token":"eyJ1c2VyX2lkIjoyMTg4MjU2NCwibGFzdGxvZ2luIjoxNTkzMzI3NzQyfQ.c39375da9af6cf24aae0349c4f0b5641.9b0e72bc9a1eea26114dc955d730603e4c11f865d43ea9595d9fd29c","path":"v1/video/info/65696"}
    ss = '{"an_stream":"https://tv-as.00ph.cn","timestamp":"' + str(int(
        time.time())) + '","an_quality":"240","token":"eyJ1c2VyX2lkIjoyMTg4MjU2NCwibGFzdGxvZ2luIjoxNTkzMzI3NzQyfQ.c39375da9af6cf24aae0349c4f0b5641.9b0e72bc9a1eea26114dc955d730603e4c11f865d43ea9595d9fd29c","path":"v1/video/info/' + video_id + '"}'

    ds = aes_encrypt_raw(request_key, ss, request_iv)
    print(ds)
    payload = 'HTpKwS4MVfB2pktFSGRzvw==.' + ds
    base_url = 'https://api.bdxxo.cn/v1/video/info/' + video_id + '?payload=' + urllib.parse.quote(payload)

    print(base_url)
    resp = requests.get(base_url)
    print(resp.text)

    # 1216557403 x-vtag
    response_headers = resp.headers
    vtag = response_headers.get('x-vtag')
    print(vtag)

    i = md5(vtag)
    print(i)
    iv = i[8:24]
    print(iv)
    new_key = md5('fe34dd6bbd3020c2fb69abe73b5b973c')
    dds = aes_decrypt(new_key.encode('utf8'),
                      resp.text,
                      iv.encode('utf8'))
    print(dds)


def decrypt_m3u8_data(base_url):
    resp = requests.get(base_url)
    print(resp.text)

    # 1216557403 x-vtag
    response_headers = resp.headers
    vtag = response_headers.get('x-vtag')
    print(vtag)

    i = md5(vtag)
    print(i)
    iv = i[8:24]
    print(iv)
    new_key = md5('fe34dd6bbd3020c2fb69abe73b5b973c')
    dds = aes_decrypt(new_key.encode('utf8'),
                      resp.text,
                      iv.encode('utf8'))
    print(dds)


if __name__ == "__main__":
    #decode_image()

    # 请求
    # {'type': 'send', 'payload': 'key:[object Object]'}
    # {'type': 'send', 'payload': 'euZN1Gg3JIwWOEWhmE7C4l5dSSRU34fyuPMXjtuoqVs=\n'}
    # {'type': 'send', 'payload': 'iv:[object Object]'}
    # {'type': 'send', 'payload': 'Eon68Zl7XqMuUmzP0cC+dQ==\n'}
    # {'type': 'send', 'payload': 'source_string:'}
    # {'type': 'send', 'payload': '{"timestamp":"1593417133","order":"time","video_type":"long","type":"uncover","page":"1","token":"eyJ1c2VyX2lkIjoyMTg4MjU2NCwibGFzdGxvZ2luIjoxNTkzMzI3NzQyfQ.c39375da9af6cf24aae0349c4f0b5641.9b0e72bc9a1eea26114dc955d730603e4c11f865d43ea9595d9fd29c","path":"v1/videos/menu/0"}'}

    # request_key = base64.decodebytes(bytes('euZN1Gg3JIwWOEWhmE7C4l5dSSRU34fyuPMXjtuoqVs=', encoding='utf8'))
    # request_iv = b'\x49\x09\x3E\x49\x6D\x29\x50\xBB\xF1\x67\x9C\x5D\x52\x77\xBF\x4E'
    # request_iv = base64.decodebytes(bytes('xTYZDR9+A9V4fMGVh1fSNA==', encoding='utf8'))
    #
    # ss = '{"timestamp":"1593567379","page":"1","token":"eyJ1c2VyX2lkIjoyMTg4MjU2NCwibGFzdGxvZ2luIjoxNTkzMzI3NzQyfQ.c39375da9af6cf24aae0349c4f0b5641.9b0e72bc9a1eea26114dc955d730603e4c11f865d43ea9595d9fd29c","path":"v1/videos/recommend/115012"}'
    #
    # ds = AES_Encrypt_raw(request_key, ss, request_iv)
    # print(ds)
    # request_iv2 = base64.decodebytes(bytes('xTYZDR9+A9V4fMGVh1fSNA==', encoding='utf8'))
    # dds = AES_Decrypt(request_key,
    #                   'FnU3ErWDIJAINm8+lEarYVLpoygtStEjh+857fpY991koQhkFrKMVLlZCcZ9k2wf+xT6SzeKjF5K4vgofUkBeAuz5uICLJsDW55y690hKclFu7Xld+IuYr8ITrz91tmTQXYHZ5OLujpY2I/XWRcNzvdbxm2OkFDMJsQcZRe2fZAzFGZjoG3k+PcpsHZJngOns8IhBd2rxjm0tyr5vLnzQCvX4wB+sqIQ4pnTOlBQk/jkNUM7lQ9Tcg/2lJRGdwi2MaEAYe1X8r7TZECmyiwVyGgBFQcpuUbq/ECiyw2xWCtt1r7yRQajyqoDb2H7+8Be',
    #                   request_iv2)
    # print(dds)
    #
    new_video_get_test()

    # rep = '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'
    #
    # request_key = base64.decodebytes(bytes('euZN1Gg3JIwWOEWhmE7C4l5dSSRU34fyuPMXjtuoqVs=', encoding='utf8'))
    # request_iv = base64.decodebytes(bytes('W8Z1MKAeHL7ufgf/XOFNzw==', encoding='utf8'))
    #
    # te = base64.decodebytes(bytes('tXsXUQQFotRuxgCH2i5dNw==', encoding='utf8'))
    # print(te)
    #
    # dds = AES_Decrypt(request_key,
    #                   rep,
    #                   request_iv)
    # print(dds)
    s = 'zKh3eskoQsIj%2FZizh%2Fuysg%3D%3D.8cV0gzp1SbuNaQram0B%2B14W3TuFVUrGzocu9F3a%2BP1l4qioKqKzrz5ZQoBKdNz%2FSOesij1T%2BTCXzK%2FclvuhIHZnsFAGav%2F5oqcJ4rGSfO4%2F%2FHc24cr%2B%2FKT6RPKo8nxu5T2nnmO%2BhxSC9YlMnvIiyNvGlqdIJw%2Fx%2FAIWaswYbC6aL99jM63dp5jXdlApAftGSYI9KrIknhZ208M0NVmCae4ZmYFxEtWQ0a4Gku5uJ%2BQnAbX%2FIkSiQ50FAS6MZd7ZV%2Fwqt0B0oJTgUmiboEN7G16MsrNqt2taBRAtedl33i6Qe2nAd7FsYzLFopoww1pf9GiiRHceS6f1ZjoosR5IrboptQp6Sh1QnT8JUO3qsj0c%3D'
    request_payload_decrypt(s)

    new_video_get_recommand_test('64852')
    new_video_get_detail_test('64852')

    decrypt_m3u8_data('https://tv-as.00ph.cn/media/240/64852.m3u8?expire=1593570576&hash=4f11da5357d1b89828a952984fef1177')