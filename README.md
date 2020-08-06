# AWVS批量扫描脚本
![awvs_config.ini](https://s1.ax1x.com/2020/08/06/agCwPs.png)

## 脚本功能
完美支持AWVS13,AWVS12两个版本的API接口

* 支持URL批量添加扫描
* 支持对批量url添加`cooKie`凭证进行爬虫扫描
* 支持结合被动扫描器进行配置扫描,如：`xray`,`w13scan`,`burp`等扫描器
* 支持一键删除所有任务
* 通过配置`awvs_config.ini`文件，支持自定义各种扫描参数，如:爬虫速度，排除路径(不扫描的目录),全局`cookie`,限制为仅包含地址和子目录
* 支持对扫描器内已有目标进行批量扫描，支持自定义扫描类型

## 使用教程

#### 1、配置好当前目前的awvs_config.ini文件
![awvs_config.ini](https://github.com/test502git/awvs13_batch_py3/blob/master/add_log/config.png)


#### 2、使用Python3运行awvs_add_url-v2.0.py
![awvs_add_url](https://github.com/test502git/awvs13_batch_py3/blob/master/add_log/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200728190739.png)


现在就可以根据自己需求进行扫描吧


#### awvs12批量添加并设置仅爬虫，配置好cookie等参数，发送到xray扫描器扫描
![awvs_add_url](https://github.com/test502git/awvs13_batch_py3/blob/master/add_log/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200728204949.png)


## AWVS安装
推荐使用`Docker`进行部署，个人也比较喜欢

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
