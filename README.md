# 免责声明
本项目仅用于安全自查，请勿利用文章内的相关工具与技术从事非法测试，如因此产生的一切不良后果与本项目无关

## awvs14-scan
修复多个Bug，config增加配置参数

针对 AWVS 14版本开发的批量扫描脚本，支持log4j漏洞专项，支持联动xray、burp、w13scan等被动批量扫描，灵活自定义

![image](https://user-images.githubusercontent.com/50769953/151646867-0af1e935-7ae2-49de-aae7-c87b849050ac.png)
![image](https://user-images.githubusercontent.com/50769953/151646798-55394213-cda2-4f55-aac8-a2f945aba6fc.png)
![image](https://user-images.githubusercontent.com/50769953/151647173-e9420a24-19f3-4031-a185-09732de66b22.png)



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


## AWVS14 推荐docker安装，本版本较新，能支持log4j版本漏洞
推荐使用docker 
```
安装
docker pull xiaomimi8/awvs14-log4j-2022

启动
docker run -it -d -p 13443:3443 xiaomimi8/awvs14-log4j-2022

用户名：admin@admin.com 密码：Admin123
```
