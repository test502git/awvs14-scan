# 免责声明
本项目仅用于安全自查，请勿利用文章内的相关工具与技术从事非法测试，如因此产生的一切不良后果与本项目无关



本工具来自知识星球-BugBounty漏洞赏金自动化：

![image](https://user-images.githubusercontent.com/50769953/167792916-20a9ee30-6f66-4f83-aa87-2c53e088565a.png)



## awvs14-scan
支持awvs14,15 修复多个Bug，config增加配置参数

config.ini 请使用编辑器更改，记事本会改会原有格式

针对 AWVS 14版本开发的批量扫描脚本，支持SpringShell\log4j\常见CVE\Bug Bounty\常见高危\SQL注入\XSS等 专项漏洞的扫描，支持联动xray、burp、w13scan等被动批量扫描，灵活自定义扫描模板

```
********************************************************************
1 【批量添加url到AWVS扫描器扫描】
2 【删除扫描器内所有目标与扫描任务】
3 【删除所有扫描任务(不删除目标)】
4 【对扫描器中已有目标，进行扫描】

请输入数字:1
选择要扫描的类型：
1 【开始 完全扫描】
2 【开始 扫描高风险漏洞】
3 【开始 扫描XSS漏洞】
4 【开始 扫描SQL注入漏洞】
5 【开始 弱口令检测】
6 【开始 Crawl Only,，建议config.ini配置好上级代理地址，联动被动扫描器】
7 【开始 扫描意软件扫描】
8 【仅添加 目标到扫描器，不做任何扫描】
9 【仅扫描apache-log4j】(请需先确保当前版本已支持log4j扫描,awvs 14.6.211220100及以上)
10 【开始扫描Bug Bounty高频漏洞】
11 【扫描已知漏洞】（常见CVE，POC等）
12 【自定义模板】
13 【仅扫描Spring4ShellCVE-2022-22965】需确保当前版本已支持

请输入数字:?
```

## 14版本脚本功能  
仅支持AWVS14版本的API接口
* 支持URL批量添加扫描
* 支持批量仅扫描apache-log4j漏洞
* 支持对批量url添加`cooKie`凭证进行爬虫扫描
* 支持对批量url添加1个或多个不同请求头
* 支持配置上级代理地址，能结合被动扫描器进行配置扫描,如：`xray`,`w13scan`,`burp`等扫描器
* 支持一键清空所有任务
* 通过配置`config.ini`文件，支持自定义各种扫描参数，如:爬虫速度，排除路径(不扫描的目录),全局`cookie`,限制为仅包含地址和子目录
* 支持对扫描器内已有目标进行批量扫描，支持自定义扫描类型



## Linux AWVS14 docker安装
推荐使用docker 
```
4月1号更新 支持Support Scanning !Spring4Shell (CVE-2022-22965) !!!

安装： docker pull  xiaomimi8/docker-awvs-14.7.220401065

启动用法： docker run -it -d -p 13443:3443 xiaomimi8/docker-awvs-14.7.220401065

登录： Username:admin@admin.com password:Admin123
```

## 赞赏码
如果对你有帮助的话要不请作者喝杯奶茶?(嘿嘿)👍 (打赏时请留言你的ID

![](https://s3.bmp.ovh/imgs/2022/02/185eb77e0285777a.png)


