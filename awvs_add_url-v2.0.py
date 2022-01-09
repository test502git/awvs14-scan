#!/usr/bin/python
# -*- coding: UTF-8 -*-
import sys,os
version = sys.version_info
if version < (3, 0):
    print('The current version is not supported, you need to use python3')
    sys.exit()
import requests
import json,ast
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import configparser
scan_label='脚本默认标签'
cf = configparser.ConfigParser()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

print('初始化中~')
try:
    cf.read(r"config.ini",encoding='utf-8')
    secs=cf.sections()
    awvs_url =cf.get('awvs_url_key','awvs_url')
    apikey = cf.get('awvs_url_key','api_key')
    input_urls=cf.get('awvs_url_key','domain_file')
    excluded_paths = ast.literal_eval(cf.get('scan_seting', 'excluded_paths'))
    limit_crawler_scope = cf.get('scan_seting', 'limit_crawler_scope')
    scan_speed = cf.get('scan_seting', 'scan_speed')
    scan_cookie = cf.get('scan_seting', 'cookie').replace('\n', '').strip()  # 处理前后空格 与换行。
except Exception as e:
    print('初始化失败，获取config.ini失败，请检查config.ini文件是否正确\n', e)
    sys.exit()


headers = {'Content-Type': 'application/json',"X-Auth": apikey}
add_count_suss=0
error_count=0
target_scan=False
target_list=[]
pages = 10


def get_status():
    try:
        r = requests.get(awvs_url + '/api/v1/targets', headers=headers, timeout=10, verify=False)
        if r.status_code==401:
            print('awvs认证失败，请检查config.ini配置的中api_key是否正确')
            sys.exit()
        if r.status_code==200 and 'targets' in str(r.text):
            pass
    except Exception as e:
        print('初始化失败，请检查config.ini文件中的awvs_url是否正确\n',e)
        sys.exit()


    print('初始化完成，配置正确')

get_status()




def get_target_list():#获取扫描器内所有目标
    global pages,target_list
    while 1:
        target_dict={}
        get_target_url=awvs_url+'/api/v1/targets?c={}&l=10'.format(str(pages))
        r = requests.get(get_target_url, headers=headers, timeout=30, verify=False)
        result = json.loads(r.content.decode())
        try:
            for targetsid in range(len(result['targets'])):
                target_dict={'target_id':result['targets'][targetsid]['target_id'],'address':result['targets'][targetsid]['address']}
                target_list.append(target_dict)
            pages=pages+10

            if len(result['targets'])==0:
                break
        except Exception as e:
            return r.text


def get_scan_status():#获取扫描状态
    try:
        global pages,target_list
        target_dict={}
        get_target_url=awvs_url+'/api/v1/me/stats'
        r = requests.get(get_target_url, headers=headers, timeout=30, verify=False)
        result = json.loads(r.content.decode())
        print('\n扫描中:',result['scans_running_count'],'等待扫描:',result['scans_waiting_count'],'已扫描:',result['scans_conducted_count'],'漏洞总数:',str(result['vuln_count'])+'\n主要漏洞')
        for xxxx in result['top_vulnerabilities']:
            print('漏洞名称:',xxxx['name'],'漏洞数量:',xxxx['count'])
    except Exception as e:
        print(e)


def addTask(url,target):
    global scan_label
    try:
        url = ''.join((url, '/api/v1/targets/add'))
        data = {"targets":[{"address": target,"description":scan_label}],"groups":[]}
        r = requests.post(url, headers=headers, data=json.dumps(data), timeout=30, verify=False)
        result = json.loads(r.content.decode())
        return result['targets'][0]['target_id']
    except Exception as e:
        return e
def scan(url,target,Crawl,user_agent,profile_id,proxy_address,proxy_port,scan_speed,limit_crawler_scope,excluded_paths,scan_cookie,is_to_scan):
    global scan_label
    scanUrl = ''.join((url, '/api/v1/scans'))
    target_id = addTask(url,target)
    if target_id:
        try:
            configuration(url,target_id,proxy_address,proxy_port,Crawl,user_agent,scan_speed,limit_crawler_scope,excluded_paths,scan_cookie,target)#配置目标参数信息
            if is_to_scan:
                data = {"target_id": target_id, "profile_id": profile_id, "incremental": False,
                        "schedule": {"disable": False, "start_date": None, "time_sensitive": False}}
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


def CustomScan():  # 增加自定义扫描log4j
    get_target_url = awvs_url + '/api/v1/scanning_profiles'
    # log4j
    post_data = {"name":"Apache Log4j RCE","custom":'true',"checks":["wvs/Scripts/PerFile","wvs/Scripts/PerFolder","wvs/Scripts/PerScheme/ASP_Code_Injection.script","wvs/Scripts/PerScheme/PHP_Deserialization_Gadgets.script","wvs/Scripts/PerScheme/Arbitrary_File_Creation.script","wvs/Scripts/PerScheme/Arbitrary_File_Deletion.script","wvs/Scripts/PerScheme/Blind_XSS.script","wvs/Scripts/PerScheme/CRLF_Injection.script","wvs/Scripts/PerScheme/Code_Execution.script","wvs/Scripts/PerScheme/Directory_Traversal.script","wvs/Scripts/PerScheme/Email_Header_Injection.script","wvs/Scripts/PerScheme/Email_Injection.script","wvs/Scripts/PerScheme/Error_Message.script","wvs/Scripts/PerScheme/Expression_Language_Injection.script","wvs/Scripts/PerScheme/File_Inclusion.script","wvs/Scripts/PerScheme/File_Tampering.script","wvs/Scripts/PerScheme/File_Upload.script","wvs/Scripts/PerScheme/Generic_Oracle_Padding.script","wvs/Scripts/PerScheme/HTTP_Parameter_Pollution.script","wvs/Scripts/PerScheme/Host_Based_Attack_Reset_Password.script","wvs/Scripts/PerScheme/LDAP_Injection.script","wvs/Scripts/PerScheme/Long_Password_Denial_of_Service.script","wvs/Scripts/PerScheme/MongoDB_Injection.script","wvs/Scripts/PerScheme/NodeJs_Injection.script","wvs/Scripts/PerScheme/PHP_Code_Injection.script","wvs/Scripts/PerScheme/RubyOnRails_Code_Injection.script","wvs/Scripts/PerScheme/Perl_Code_Injection.script","wvs/Scripts/PerScheme/PHP_User_Controlled_Vulns.script","wvs/Scripts/PerScheme/Rails_Mass_Assignment.script","wvs/Scripts/PerScheme/Rails_Where_SQL_Injection.script","wvs/Scripts/PerScheme/Rails_render_inline_RCE.script","wvs/Scripts/PerScheme/Remote_File_Inclusion_XSS.script","wvs/Scripts/PerScheme/Script_Source_Code_Disclosure.script","wvs/Scripts/PerScheme/Server_Side_Request_Forgery.script","wvs/Scripts/PerScheme/Sql_Injection.script","wvs/Scripts/PerScheme/Struts_RCE_S2-053_CVE-2017-12611.script","wvs/Scripts/PerScheme/Struts_RCE_S2_029.script","wvs/Scripts/PerScheme/Unsafe_preg_replace.script","wvs/Scripts/PerScheme/XFS_and_Redir.script","wvs/Scripts/PerScheme/XML_External_Entity_Injection.script","wvs/Scripts/PerScheme/XPath_Injection.script","wvs/Scripts/PerScheme/XSS.script","wvs/Scripts/PerScheme/ESI_Injection.script","wvs/Scripts/PerScheme/Java_Deserialization.script","wvs/Scripts/PerScheme/Pickle_Serialization.script","wvs/Scripts/PerScheme/Python_Code_Injection.script","wvs/Scripts/PerScheme/Argument_Injection.script","wvs/Scripts/PerScheme/DotNet_BinaryFormatter_Deserialization.script","wvs/Scripts/PerScheme/Apache_Solr_Parameter_Injection.script","wvs/Scripts/PerScheme/Cmd_Hijack_Windows.script","wvs/Scripts/PerScheme/JWT_Param_Audit.script","wvs/Scripts/PerServer","wvs/Scripts/PostCrawl","wvs/Scripts/PostScan","wvs/Scripts/WebApps","wvs/RPA","wvs/Crawler","wvs/location","wvs/httpdata","wvs/target/rails_sprockets_path_traversal.js","wvs/target/web_cache_poisoning.js","wvs/target/aux_systems_ssrf.js","wvs/target/proxy_misrouting_ssrf.js","wvs/target/http_01_ACME_challenge_xss.js","wvs/target/java_melody_detection_plus_xxe.js","wvs/target/uwsgi_path_traversal.js","wvs/target/weblogic_rce_CVE-2018-3245.js","wvs/target/php_xdebug_rce.js","wvs/target/nginx_integer_overflow_CVE-2017-7529.js","wvs/target/jupyter_notebook_rce.js","wvs/target/hadoop_yarn_resourcemanager.js","wvs/target/couchdb_rest_api.js","wvs/target/activemq_default_credentials.js","wvs/target/apache_mod_jk_access_control_bypass.js","wvs/target/mini_httpd_file_read_CVE-2018-18778.js","wvs/target/osgi_management_console_default_creds.js","wvs/target/docker_engine_API_exposed.js","wvs/target/docker_registry_API_exposed.js","wvs/target/jenkins_audit.js","wvs/target/thinkphp_5_0_22_rce.js","wvs/target/uwsgi_unauth.js","wvs/target/fastcgi_unauth.js","wvs/target/apache_balancer_manager.js","wvs/target/cisco_ise_stored_xss.js","wvs/target/horde_imp_rce.js","wvs/target/nagiosxi_556_rce.js","wvs/target/next_js_arbitrary_file_read.js","wvs/target/php_opcache_status.js","wvs/target/opencms_solr_xxe.js","wvs/target/redis_open.js","wvs/target/memcached_open.js","wvs/target/Weblogic_async_rce_CVE-2019-2725.js","wvs/target/Weblogic_T3_XXE_CVE-2019-2647.js","wvs/target/RevProxy_Detection.js","wvs/target/cassandra_open.js","wvs/target/nagiosxi_sqli_CVE-2018-8734.js","wvs/target/backdoor_bootstrap_sass.js","wvs/target/apache_spark_audit.js","wvs/target/fortigate_file_reading.js","wvs/target/pulse_sslvpn_file_reading.js","wvs/target/SAP_Hybris_virtualjdbc_RCE_CVE-2019-0344.js","wvs/target/webmin_rce_1_920_CVE-2019-15107.js","wvs/target/Weblogic_T3_XXE_CVE-2019-2888.js","wvs/target/citrix_netscaler_CVE-2019-19781.js","wvs/target/DotNet_HTTP_Remoting.js","wvs/target/opensearch-target.js","wvs/target/adminer-4.6.2-file-disclosure-vulnerability.js","wvs/target/apache_mod_rewrite_open_redirect_CVE-2019-10098.js","wvs/target/default_apple-app-site-association.js","wvs/target/golang-debug-pprof.js","wvs/target/openid_connect_discovery.js","wvs/target/nginx-plus-unprotected-status.js","wvs/target/nginx-plus-unprotected-api.js","wvs/target/nginx-plus-unprotected-dashboard.js","wvs/target/nginx-plus-unprotected-upstream.js","wvs/target/Kentico_CMS_Audit.js","wvs/target/Rails_DoubleTap_RCE_CVE-2019-5418.js","wvs/target/Oracle_EBS_Audit.js","wvs/target/rce_sql_server_reporting_services.js","wvs/target/liferay_portal_jsonws_rce.js","wvs/target/php_opcache_gui.js","wvs/target/check_acumonitor.js","wvs/target/spring_cloud_config_server_CVE-2020-5410.js","wvs/target/f5_big_ip_tmui_rce_CVE-2020-5902.js","wvs/target/rack_mini_profiler_information_disclosure.js","wvs/target/grafana_ssrf_rce_CVE-2020-13379.js","wvs/target/h2-console.js","wvs/target/jolokia_xxe.js","wvs/target/rails_rce_locals_CVE-2020-8163.js","wvs/target/Cisco_ASA_Path_Traversal_CVE-2020-3452.js","wvs/target/DNN_Deser_Cookie_CVE-2017-9822.js","wvs/target/404_text_search.js","wvs/target/totaljs_dir_traversal_CVE-2019-8903.js","wvs/target/OFBiz_xmlrpc_deser_rce_CVE-2020-9496.js","wvs/target/http_redirections.js","wvs/target/apache_zookeeper_open.js","wvs/target/apache_kafka_open.js","wvs/target/nette_framework_rce_CVE-2020-15227.js","wvs/target/vmware_vcenter_unauth_file_read.js","wvs/target/mobile_iron_rce_CVE-2020-15505.js","wvs/target/web_cache_poisoning_dos.js","wvs/target/prototype_pollution_target.js","wvs/target/openfire_admin_console_ssrf_CVE-2019-18394.js","wvs/target/weblogic_rce_CVE-2020-14882.js","wvs/target/Weblogic_IIOP_RCE_CVE-2020-2551.js","wvs/target/Odoo_audit.js","wvs/target/citrix_xenmobile_arbitrary_file_read_CVE-2020-8209.js","wvs/target/sonarqube_default_credentials.js","wvs/target/common_api_endpoints.js","wvs/target/Unomi_MVEL_RCE_CVE-2020-13942.js","wvs/target/symfony_weak_secret_rce.js","wvs/target/lucee_arbitrary_file_write.js","wvs/target/dynamic_rendering_engines.js","wvs/target/open_prometheus.js","wvs/target/open_monitoring.js","wvs/target/apache_flink_path_traversal_CVE-2020-17519.js","wvs/target/imageresizer_debug.js","wvs/target/unprotected_apache_nifi.js","wvs/target/unprotected_kong_gateway_adminapi_interface.js","wvs/target/sap_solution_manager_rce_CVE-2020-6207.js","wvs/target/sonicwall_ssl_vpn_rce_jarrewrite.js","wvs/target/nodejs_debugger_open.js","wvs/target/vmware_vcenter_server_unauth_rce_CVE-2021-21972.js","wvs/target/paloalto-pan-os-xss-CVE-2020-2036.js","wvs/target/golang_delve_debugger_open.js","wvs/target/microsoft_exchange-server-ssrf-CVE-2021-26855.js","wvs/target/python_debugpy_debugger_open.js","wvs/target/AppWeb_auth_bypass_CVE-2018-8715.js","wvs/target/OFBiz_SOAPService_deser_rce_CVE-2021-26295.js","wvs/target/vhost_files_locs_misconfig.js","wvs/target/cockpit_nosqli_CVE-2020-35847.js","wvs/target/f5_iControl_REST_RCE_CVE-2021-22986.js","wvs/target/Cisco_RV_auth_bypass_CVE-2021-1472.js","wvs/target/web_installer_exposed.js","wvs/target/ntopng_auth_bypass_CVE-2021-28073.js","wvs/target/request_smuggling.js","wvs/target/Hashicorp_Consul_exposed.js","wvs/target/django_debug_toolbar.js","wvs/target/VMware_vRealize_SSRF_CVE-2021-21975.js","wvs/target/GravCMS_unauth_RCE_CVE-2021-21425.js","wvs/target/caddy_unprotected_api.js","wvs/target/dragonfly_arbitrary_file_read_CVE-2021-33564.js","wvs/target/bitrix_audit.js","wvs/target/open_redirect.js","wvs/target/gitlab_audit.js","wvs/target/nacos_auth_bypass_CVE-2021-29441.js","wvs/target/sap_bo_bip_ssrf_CVE-2020-6308.js","wvs/target/detect_apache_shiro_server.js","wvs/target/jetty_concat_inf_disc_CVE-2021-28164.js","wvs/target/RethinkDB_open.js","wvs/target/spring_boot_actuator_logview_path_trav_CVE-2021-21234.js","wvs/target/open_webpagetest.js","wvs/target/buddypress_rest_api_privesc_CVE-2021-21389.js","wvs/target/Hasura_GraphQL_SSRF.js","wvs/target/grandnode_path_traversal_CVE-2019-12276.js","wvs/target/SearchBlox_File_Inclusion_CVE-2020-35580.js","wvs/target/Zimbra_SSRF_CVE-2020-7796.js","wvs/target/jetty_inf_disc_CVE-2021-34429.js","wvs/target/Cisco_ASA_XSS_CVE-2020-3580.js","wvs/target/haproxy_unprotected_api.js","wvs/target/kong_unprotected_api.js","wvs/target/OData_feed_accessible_anonymously.js","wvs/target/Confluence_OGNL_Injection_CVE-2021-26084.js","wvs/target/microsoft_exchange_preauth_path_confusion_CVE-2021-34473.js","wvs/target/Atlassian_Jira_File_Read_CVE-2021-26086.js","wvs/target/ManageEngine_ADSelfService_Plus_auth_bypass_CVE-2021-40539.js","wvs/target/Django_Debug_Mode.js","wvs/target/Payara_Micro_File_Read_CVE-2021-41381.js","wvs/target/keycloak_request_uri_SSRF_CVE-2020-10770.js","wvs/target/apache_mod_proxy_SSRF_CVE-2021-40438.js","wvs/target/apache_insecure_path_norm_CVE-2021-41773_CVE-2021-42013.js","wvs/target/gitlab_exiftool_rce_CVE-2021-22205.js","wvs/target/http2/http2_pseudo_header_ssrf.js","wvs/target/Sitecore_XP_RCE_CVE-2021-42237.js","wvs/target/http2/http2_misrouting_ssrf.js","wvs/target/http2/http2_web_cache_poisoning.js","wvs/target/http2/http2_web_cache_poisoning_dos.js","wvs/input_group","wvs/deepscan","wvs/custom-scripts","wvs/MalwareScanner"]}

    r = requests.post(get_target_url, data=json.dumps(post_data), headers=headers, timeout=30, verify=False)
    result = json.loads(r.content.decode())
    #print(result['profile_id'])
    get_target_url = awvs_url + 'api/v1/scanning_profiles'
    r = requests.get(get_target_url, headers=headers, timeout=30, verify=False)
    result = json.loads(r.content.decode())
    return result['scanning_profiles'][8]['profile_id']


def main():
    global add_count_suss,error_count,target_scan,scan_label,input_urls,excluded_paths,limit_crawler_scope,scan_speed,scan_cookie
########################################################AWVS扫描配置参数#########################################
    Crawl = False                   #默认False，不会启用
    proxy_address = '127.0.0.1'     #不要删，不会启用
    proxy_port = '777'              #不要删，不会启用
    input_urls=input_urls
    excluded_paths=excluded_paths
    limit_crawler_scope=limit_crawler_scope
    scan_speed = scan_speed
    scan_cookie=scan_cookie
    mod_id = {
        "1": "11111111-1111-1111-1111-111111111111",                 # 完全扫描
        "2": "11111111-1111-1111-1111-111111111112",                # 高风险漏洞
        "3": "11111111-1111-1111-1111-111111111116",                # XSS漏洞
        "4": "11111111-1111-1111-1111-111111111113",                # SQL注入漏洞
        "5": "11111111-1111-1111-1111-111111111115",                # 弱口令检测
        "6": "11111111-1111-1111-1111-111111111117",                # Crawl Only
        "7": "11111111-1111-1111-1111-111111111120",                # 恶意软件扫描
        "8": "11111111-1111-1111-1111-111111111120",                 #仅添加，这行不会生效
        "9": "CustomScan",
    }
    if target_scan==False:
        print("""选择要扫描的类型：
1 【开始 完全扫描】
2 【开始 扫描高风险漏洞】
3 【开始 扫描XSS漏洞】
4 【开始 扫描SQL注入漏洞】
5 【开始 弱口令检测】
6 【开始 Crawl Only,仅爬虫，将进入被动扫描器地址设置(14版本存在bug)】
7 【开始 扫描意软件扫描】
8 【仅添加 目标到扫描器，不做任何扫描】
9 【仅扫描】apache-log4j(请先确保当前版本已支持log4j扫描,awvs 14.6.211220100)""")
    else:
        print("""对已有目标进行扫描，选择要扫描的类型：
1 【完全扫描】
2 【扫描高风险漏洞】
3 【扫描XSS漏洞】
4 【扫描SQL注入漏洞】
5 【弱口令检测】
6 【Crawl Only,仅爬虫，将进入被动扫描器地址设置(14版本存在bug)】
7 【扫描意软件扫描】
9 【仅扫描】apache-log4j(请先确保当前版本已支持log4j扫描,awvs 14.6.211220100)""")

    scan_type = str(input('请输入数字:'))
    scan_label = str(input('输入本次要扫描的资产标签（可空）:'))
    try:
        is_to_scan = True
        if target_scan==False:
            if '8'==scan_type:
                is_to_scan = False
        profile_id=mod_id[scan_type]#获取扫描漏洞类型
        if '9' == scan_type:
            profile_id=CustomScan()
    except Exception as e:
        print('输入有误，检查',e)
        sys.exit()
    if profile_id=='11111111-1111-1111-1111-111111111117':
        print('【如 联动xray扫描器】： xray_windows_amd64.exe webscan --listen 192.168.2.2:7777')
        proxy_address=str(input('被动扫描器监听IP地址(如：192.168.2.2)'))
        proxy_port=str(input('被动扫描器监听端口(如：7777)：'))
        Crawl = True
########################################################扫描配置参数#########################################

    targets = open(input_urls, 'r', encoding='utf-8').read().split('\n')
    user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21" #扫描默认UA头
    if Crawl:#仅调用xray进行代理扫描
        profile_id = "11111111-1111-1111-1111-111111111117"
    if target_scan==False:
        for target in targets:
            if target:
                target = target.strip()
                #if '://' not in target and 'http' not in target:
                if 'http' not in target[0:7]:
                    target='http://'+target

                target_state=scan(awvs_url,target,Crawl,user_agent,profile_id,proxy_address,int(proxy_port),scan_speed,limit_crawler_scope,excluded_paths,scan_cookie,is_to_scan)
                if target_state!=2:
                    open('./add_log/success.txt','a',encoding='utf-8').write(target+'\n')
                    add_count_suss=add_count_suss+1
                    print("{0} 已加入到扫描队列 ，第:".format(target),str(add_count_suss))
                elif target_state==2:
                    pass
                else:
                    open('./add_log/error_url.txt', 'a', encoding='utf-8').write(target + '\n')
                    error_count=error_count+1
                    print("{0} 添加失败".format(target),str(error_count))
    elif target_scan==True:
        get_target_list()
        scanUrl2= ''.join((awvs_url, '/api/v1/scans'))
        for target_for in target_list:
            data = {"target_id": target_for['target_id'], "profile_id": profile_id, "incremental": False,
                    "schedule": {"disable": False, "start_date": None, "time_sensitive": False}}
            configuration(awvs_url, target_for['target_id'], proxy_address, proxy_port, Crawl, user_agent, scan_speed,
                          limit_crawler_scope,
                          excluded_paths, scan_cookie, target_for['address'])  #已有目标扫描时配置
            try:
                response = requests.post(scanUrl2, data=json.dumps(data), headers=headers, timeout=30, verify=False)
                result = json.loads(response.content)
                if 'profile_id' in str(result) and 'target_id' in str(result):
                    print(target_for['address'],'添加到扫描器队列，开始扫描')
            except Exception as e:
                print(str(target_for['address'])+' 扫描失败 ',e)


if __name__ == '__main__':

    print(    """
********************************************************************      
AWVS批量添加目标，批量扫描log4j，支持awvs13批量联动被动扫描器等功能                                                                                                        
作者微信：SRC-ALL
********************************************************************
1 【批量添加url到AWVS扫描器扫描】
2 【一键删除扫描器内所有目标】
3 【对扫描器中已有目标，进行扫描】 
4 【获取当前扫描状态】 
    """)
    selection=int(input('请输入数字:'))
    if selection==1:
        main()
    elif selection==2:
        delete_targets()
    elif selection==3:
        target_scan=True
        main()
    elif selection==4:
        get_scan_status()
