#!/usr/bin/python
# -*- coding: UTF-8 -*-
import requests
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


#正式
#awvs_url = 'https://207.148.15.52:13443'     #awvs url
#apikey = '1986ad8c0a5b3df4d7028d5f3c06e936c332a06fbd95f49b6a1e057d4ef5630cf'    #API


#测试
awvs_url = 'https://116.85.13.98'     #awvs url
apikey = '1986ad8c0a5b3df4d7028d5f3c06e936c582a66098e2f4d71acfe63ffd649d3b3'    #API



headers = {'Content-Type': 'application/json',"X-Auth": apikey}
add_count_suss=0
error_count=0
def addTask(url,target):
    try:
        url = ''.join((url, '/api/v1/targets/add'))
        data = {"targets":[{"address": target,"description":""}],"groups":[]}
        r = requests.post(url, headers=headers, data=json.dumps(data), timeout=30, verify=False)
        result = json.loads(r.content.decode())
        return result['targets'][0]['target_id']
    except Exception as e:
        return e
def scan(url,target,Crawl,user_agent,profile_id,proxy_address,proxy_port,scan_speed,limit_crawler_scope,excluded_paths,scan_cookie):
    scanUrl = ''.join((url, '/api/v1/scans'))
    target_id = addTask(url,target)

    if target_id:
        data = {"target_id": target_id, "profile_id": profile_id, "incremental": False, "schedule": {"disable": False, "start_date": None, "time_sensitive": False}}
        try:
            configuration(url,target_id,proxy_address,proxy_port,Crawl,user_agent,scan_speed,limit_crawler_scope,excluded_paths,scan_cookie,target)#配置目标
            response = requests.post(scanUrl, data=json.dumps(data), headers=headers, timeout=30, verify=False)
            result = json.loads(response.content)
            return result['target_id']

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
    #print(r.text)

def main():
    global add_count_suss,error_count
########################################################AWVS扫描配置参数#########################################
    Crawl = False                   #是否启动代理扫描
    input_urls='url.txt'            #输入的url文件
    proxy_address = '127.0.0.1'     #被动扫描器代理地址
    proxy_port = '8888'             #被动扫描器代理端口

    excluded_paths	=['quit','exit','logout','Logout','delete','DELETE']         #排除的路径或操作,建议添加Cookie后再添加。

    limit_crawler_scope=False       #将抓取限制为仅包含地址和子目录 值:true(默认)/False
    scan_speed = 'moderate'         # 扫描速度，由慢到快:sequential slow moderate fast， 速度越快，遗漏越多，则之相反。

    # 设置所有批量url的 统一Cookie，可以更深度扫描，
    scan_cookie="""
    face=auto; locale=zh_CN; CoremailReferer=https%3A%2F%2Fcrmail.crc.com.cn%2F; Coremail.sid=CAOMjwiPhSzsbqqrtTPPInyfDGBcfVDQ
    """.replace('\n','').strip()#处理前后空格 与换行。

    mod_id = {
        "full_scan": "11111111-1111-1111-1111-111111111111",                 # 完全扫描
        "high_risk_vul": "11111111-1111-1111-1111-111111111112",             # 高风险漏洞
        "cross_site_vul": "11111111-1111-1111-1111-111111111116",            # XSS漏洞
        "sql_inject_vul": "11111111-1111-1111-1111-111111111113",            # SQL注入漏洞
        "week_pass_vul": "11111111-1111-1111-1111-111111111115",             # 弱口令检测
        "crawl_only": "11111111-1111-1111-1111-111111111117",                # Crawl Only
        "malware_scan": "11111111-1111-1111-1111-111111111120"               # 恶意软件扫描
    }
    profile_id = mod_id['crawl_only']   #扫描类型

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
        if scan(awvs_url,target,Crawl,user_agent,profile_id,proxy_address,int(proxy_port),scan_speed,limit_crawler_scope,excluded_paths,scan_cookie):
            open('./add_log/success.txt','a',encoding='utf-8').write(target+'\n')
            add_count_suss=add_count_suss+1
            print("{0} 添加成功,加入到扫描队列 ，第:".format(target),str(add_count_suss))
        else:
            open('./add_log/error_url.txt', 'a', encoding='utf-8').write(target + '\n')
            error_count=error_count+1
            print("{0} 添加失败".format(target),str(error_count))

if __name__ == '__main__':
    main()