#!/usr/bin/python
# -*- coding: UTF-8 -*-

#添加cookie

testdaa=r"""
localSelectedPros=%7B%22base%22%3A%5B%7B%22skuId%22%3A%2236752642%22%2C%22num%22%3A%221%22%7D%5D%7D;QCM_PLATFORM=11;isIShowWebview="";P00002="";P00003=""


""".replace('\n','')

text={"url":"http://baidu.com","cookie":testdaa}


#print(text)

taget='sgp.ali.http.bigtap.lb.mi.com'


if 'http' not in taget[0:7]:
    print(1)

