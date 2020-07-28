# AWVS批量扫描脚本

## 脚本功能
完美支持AWVS13,AWVS12两个版本的API接口

* 支持URL批量添加扫描
* 支持添加`cooKie`凭证进行扫描
* 支持结合被动扫描器进行配置扫描,如：`xray`,`w13scan`,`burp`等扫描器
* 支持一键删除所有任务
* 通过配置`awvs_config.ini`文件，支持自定义各种扫描参数，如:爬虫速度，排除路径(不扫描的目录),全局`cookie`,限制为仅包含地址和子目录
* 支持对扫描器内已有目标进行批量扫描，支持自定义扫描类型

## 使用教程

#### 1、配置好当前目前的awvs_config.ini文件
图片


#### 2、使用Python3运行awvs_add_url-v2.0.py
图片


现在就可以根据自己需求进行扫描吧。


## AWVS安装
推荐使用`Docker`进行部署，个人也比较喜欢。

```
docker pull vouu/acunetix
```

##### 运行
```
docker run -it -d --storage-opt size=40G -m 1024 -p 443:3443 vouu/acunetix
```
 --storage-opt size=40G #指设置改容器的rootfs大小。默认Docker只有10G大小，对于AWVS这样的扫描器，域名一多，肯定是不够用的啦，同学们自己也可以根据自己主机的配置合理选择。
 -m 1024                #指AWVS容器占用内存最高为1024M，这也是防止内存占满导致主机崩溃，同学们自己也可以根据自己主机的配置合理选择。


##### 登陆信息
```
地址：https://localhost
邮箱：contact@manhtuong.net
密码 ：Abcd1234
```
