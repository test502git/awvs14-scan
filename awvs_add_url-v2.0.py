#!/usr/bin/python
# -*- coding: UTF-8 -*-
import sys
version = sys.version_info
if version < (3, 0):
    print('The current version is not supported, you need to use python3')
    sys.exit()
import requests
import json,ast
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import configparser
cf = configparser.ConfigParser()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
cf.read(r"awvs_config.ini",encoding='utf-8')
secs=cf.sections()
awvs_url =cf.get('awvs_url_key','awvs_url')
apikey = cf.get('awvs_url_key','api_key')
headers = {'Content-Type': 'application/json',"X-Auth": apikey}
add_count_suss=0
error_count=0
def addTask(url,target):
    try:
        url = ''.join((url, '/api/v1/targets/add'))
        data = {"targets":[{"address": target,"description":"此url为脚本添加"}],"groups":[]}
        r = requests.post(url, headers=headers, data=json.dumps(data), timeout=30, verify=False)
        result = json.loads(r.content.decode())
        return result['targets'][0]['target_id']
    except Exception as e:
        return e
def scan(url,target,Crawl,user_agent,profile_id,proxy_address,proxy_port,scan_speed,limit_crawler_scope,excluded_paths,scan_cookie,is_to_scan):
    scanUrl = ''.join((url, '/api/v1/scans'))
    target_id = addTask(url,target)
    if target_id:
        data = {"target_id": target_id, "profile_id": profile_id, "incremental": False, "schedule": {"disable": False, "start_date": None, "time_sensitive": False}}
        try:
            configuration(url,target_id,proxy_address,proxy_port,Crawl,user_agent,scan_speed,limit_crawler_scope,excluded_paths,scan_cookie,target)#配置目标参数信息
            if is_to_scan:
                response = requests.post(scanUrl, data=json.dumps(data), headers=headers, timeout=30, verify=False)
                result = json.loads(response.content)
                return result['target_id']
            else:
                print(target, '目标仅添加成功')
                return 2

        except Exception as e:
            print(e)


def configuration(url,target_id,proxy_address,proxy_port,Crawl,user_agent,scan_speed,limit_crawler_scope,excluded_paths,scan_cookie,target):#配置目标
    configuration_url = ''.join((url,'/api/v1/targets/{0}/configuration'.format(target_id)))
    if scan_cookie != '':
        data = {"scan_speed":scan_speed,"login":{"kind":"none"},"ssh_credentials":{"kind":"none"},"sensor": False,"user_agent": user_agent,"case_sensitive":"auto","limit_crawler_scope": limit_crawler_scope,"excluded_paths":excluded_paths,"authentication":{"enabled": False},"proxy":{"enabled": Crawl,"protocol":"http","address":proxy_address,"port":proxy_port},"technologies":[],"custom_headers":[],"custom_cookies":[{"url":target,"cookie":scan_cookie}],"debug":False,"client_certificate_password":"","issue_tracker_id":"","excluded_hours_id":""}
    else:
        data = {"scan_speed": scan_speed, "login": {"kind": "none"}, "ssh_credentials": {"kind": "none"},
                "sensor": False, "user_agent": user_agent, "case_sensitive": "auto",
                "limit_crawler_scope": limit_crawler_scope, "excluded_paths": excluded_paths,
                "authentication": {"enabled": False},
                "proxy": {"enabled": Crawl, "protocol": "http", "address": proxy_address, "port": proxy_port},
                "technologies": [], "custom_headers": [], "custom_cookies": [],
                "debug": False, "client_certificate_password": "", "issue_tracker_id": "", "excluded_hours_id": ""}

    r = requests.patch(url=configuration_url,data=json.dumps(data), headers=headers, timeout=30, verify=False)
    #print(configuration_url,r.text)

def delete_targets():#删除全部扫描目标
    global awvs_url,apikey,headers
    while 1:
        quer='/api/v1/targets'
        try:
            r = requests.get(awvs_url+quer, headers=headers, timeout=30, verify=False)
            result = json.loads(r.content.decode())
            if int(result['pagination']['count'])==0:
                print('已全部删除扫描目标，目前为空')
                return 0
            for targetsid in range(len(result['targets'])):
                targets_id=result['targets'][targetsid]['target_id']
                targets_address = result['targets'][targetsid]['address']
                #print(targets_id,targets_address)
                try:
                    del_log=requests.delete(awvs_url+'/api/v1/targets/'+targets_id,headers=headers, timeout=30, verify=False)
                    if del_log.status_code == 204:
                        print(targets_address,' 删除目标成功')
                except Exception as e:
                    print(targets_address,e)
        except Exception as e:
            print(awvs_url+quer,e)

def main():
    global add_count_suss,error_count
########################################################AWVS扫描配置参数#########################################
    Crawl = False                   #默认False，不会启用
    proxy_address = '127.0.0.1'     #不要删，不会启用
    proxy_port = '777'              #不要删，不会启用
    input_urls=cf.get('awvs_url_key','domain_file')
    excluded_paths=ast.literal_eval(cf.get('scan_seting','excluded_paths'))
    limit_crawler_scope=cf.get('scan_seting','limit_crawler_scope')
    scan_speed = cf.get('scan_seting','scan_speed')
    scan_cookie=cf.get('scan_seting','cookie').replace('\n','').strip()#处理前后空格 与换行。
    mod_id = {
        "1": "11111111-1111-1111-1111-111111111111",                 # 完全扫描
        "2": "11111111-1111-1111-1111-111111111112",                # 高风险漏洞
        "3": "11111111-1111-1111-1111-111111111116",                # XSS漏洞
        "4": "11111111-1111-1111-1111-111111111113",                # SQL注入漏洞
        "5": "11111111-1111-1111-1111-111111111115",                # 弱口令检测
        "6": "11111111-1111-1111-1111-111111111117",                # Crawl Only
        "7": "11111111-1111-1111-1111-111111111120",                # 恶意软件扫描
        "8": "11111111-1111-1111-1111-111111111120"                 #仅添加，这行不会生效
    }
    print("""选择要扫描的类型：
1 【完全扫描】
2 【扫描高风险漏洞】
3 【扫描XSS漏洞】
4 【扫描SQL注入漏洞】
5 【弱口令检测】
6 【Crawl Only,仅爬虫，将进入被动扫描器地址设置】
7 【扫描意软件扫描】
8 【仅添加目标到扫描器，不做任何扫描】""")
    scan_type = str(input('请输入数字:'))
    try:
        is_to_scan = True
        if '8'==scan_type:
            is_to_scan = False
        profile_id=mod_id[scan_type]

    except Exception as e:
        print('输入有误，检查',e)
        sys.exit()
    if profile_id=='11111111-1111-1111-1111-111111111117':
        proxy_address=str(input('输入被动扫描器监听IP地址(如：127.0.0.1)：'))
        proxy_port=str(input('输入被动扫描器监听端口(如：7777)：'))
        Crawl = True
########################################################扫描配置参数#########################################

    targets = open(input_urls, 'r', encoding='utf-8').read().split('\n')
    user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21" #扫描默认UA头
    if Crawl:#仅调用xray进行代理扫描
        profile_id = "11111111-1111-1111-1111-111111111117"
    for target in targets:
        target = target.strip()
        #if '://' not in target and 'http' not in target:
        if 'http' not in target[0:7]:
            target='http://'+target

        target_state=scan(awvs_url,target,Crawl,user_agent,profile_id,proxy_address,int(proxy_port),scan_speed,limit_crawler_scope,excluded_paths,scan_cookie,is_to_scan)
        if target_state!=2:
            open('./add_log/success.txt','a',encoding='utf-8').write(target+'\n')
            add_count_suss=add_count_suss+1
            print("{0} 添加成功,加入到扫描队列 ，第:".format(target),str(add_count_suss))
        elif target_state==2:
            pass
        else:
            open('./add_log/error_url.txt', 'a', encoding='utf-8').write(target + '\n')
            error_count=error_count+1
            print("{0} 添加失败".format(target),str(error_count))
if __name__ == '__main__':

    print(    """
1 【批量添加url到AWVS扫描器扫描】
2 【一键删除扫描器内所有目标】
3 【对扫描器中已有目标，进行扫描】    开发中
    """)
    selection=int(input('请输入数字:'))
    if selection==1:
        main()
    elif selection==2:
        delete_targets()
