# AWVS13、14批量扫描脚本，支持批量代理
![awvs_config.ini](https://s1.ax1x.com/2020/08/06/agCwPs.png)


## 联动Xray说明一下 
如果AWVS爬虫请求太多，此时发送给Xray，可能会占满Xray队列(max_length)，导致代理阻塞，由于Xray的阻塞，AWVS会导致爬虫超时，这个在Xray文档中有说明，所以在批量之前 ，尽可能把Xray的max_length的值设成很大

## 脚本功能
支持AWVS13,及14的API接口

* 支持URL批量添加扫描
* 支持对批量url添加`cooKie`凭证进行爬虫扫描
* 支持结合被动扫描器进行配置扫描,如：`xray`,`w13scan`,`burp`等扫描器
* 支持一键删除所有任务
* 通过配置`awvs_config.ini`文件，支持自定义各种扫描参数，如:爬虫速度，排除路径(不扫描的目录),全局`cookie`,限制为仅包含地址和子目录
* 支持对扫描器内已有目标进行批量扫描，支持自定义扫描类型

## 使用教程


awvs_config.ini请使用专业编辑器打开，记事本会改变原有格式，导致报错

#### 1、配置好当前目前的awvs_config.ini文件
![awvs_config.ini](https://github.com/test502git/awvs13_batch_py3/blob/master/add_log/config.png)


#### 2、使用Python3运行awvs_add_url-v2.0.py
![awvs_add_url](https://github.com/test502git/awvs13_batch_py3/blob/master/add_log/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200728190739.png)


现在就可以根据自己需求进行扫描吧


#### awvs13批量添加并设置仅爬虫，配置好cookie等参数，发送到xray扫描器扫描
![awvs_add_url](https://github.com/test502git/awvs13_batch_py3/blob/master/add_log/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200728204949.png)


## AWVS安装
推荐使用`Docker`进行部署，个人也比较喜欢


