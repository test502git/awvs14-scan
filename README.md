# 免责声明
本项目仅用于安全自查，请勿利用文章内的相关工具与技术从事非法测试，如因此产生的一切不良后果与本项目无关


如果觉得还不错，请给本项目一个star

# AWVS13\14 api脚本
![awvs_config.ini](https://s4.ax1x.com/2022/01/01/T5TeoR.png)




## 2022年1月1号，新增支持批量扫描log4j漏洞

### log4j靶场 地址：http://d63bb2586.lab.aqlab.cn/  可测试效果



1-9-标签，标签可不输
![f16321066fa883e8c685ad99fd2c140](https://s4.ax1x.com/2022/01/01/T5T5XF.png)
![f16321066fa883e8c685ad99fd2c140](https://s4.ax1x.com/2022/01/01/T5HAa9.png)
## AWVS14，本版本支持log4j版本漏洞
推荐使用docker 
```
安装
docker pull xiaomimi8/awvs14-log4j-2022

启动
docker run -it -d -p 13443:3443 xiaomimi8/awvs14-log4j-2022

用户名：admin@admin.com 密码：Admin123 
```

## 脚本功能
支持AWVS13、14的API接口

* 支持URL批量添加扫描
* 支持批量扫描apache-log4j漏洞
* 支持对批量url添加`cooKie`凭证进行爬虫扫描
* 支持结合被动扫描器进行配置扫描,如：`xray`,`w13scan`,`burp`等扫描器(适用13版本)
* 支持一键删除所有任务
* 通过配置`awvs_config.ini`文件，支持自定义各种扫描参数，如:爬虫速度，排除路径(不扫描的目录),全局`cookie`,限制为仅包含地址和子目录
* 支持对扫描器内已有目标进行批量扫描，支持自定义扫描类型

## 常规使用教程

### awvs_config.ini请使用专业编辑器打开，记事本会改变原有格式，导致报错

#### 1、配置好当前目前的awvs_config.ini文件
![awvs_config.ini](https://github.com/test502git/awvs13_batch_py3/blob/master/add_log/config.png)


#### 2、使用Python3运行awvs_add_url-v2.0.py
![awvs_add_url](https://github.com/test502git/awvs13_batch_py3/blob/master/add_log/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200728190739.png)


现在就可以根据自己需求进行扫描吧

如其他用法
#### awvs13批量添加并设置仅爬虫，配置好cookie等参数，发送到xray扫描器扫描
![awvs_add_url](https://github.com/test502git/awvs13_batch_py3/blob/master/add_log/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200728204949.png)



