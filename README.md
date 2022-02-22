# ThinkPHP5.x RCE漏洞检测&利用工具
**一、说明**


要求环境：Python2.7

该工具可以轻松的对使用ThinkPHP5框架的网站进行漏洞检测、利用

**二、下载**
```
git clone https://github.com/HGDIS/ThinkPHP5-RCE.git
```

**三、使用**

python2 tp5_rce.py -h 查看使用手册

python2 tp5_rce.py --version 查看版本

python2 tp5_rce.py -u http://www.xxx.com 检测单个url

python2 tp5_rce.py -f url_file.txt 批量检测url

python2 tp5_rce.py -u http://www.xxx.com --shell 进入shell模式
