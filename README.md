![logo](https://raw.githubusercontent.com/P0cL4bs/WiFi-Pumpkin/master/docs/logo.png)

[![build](https://travis-ci.org/P0cL4bs/WiFi-Pumpkin.svg)](https://travis-ci.org/P0cL4bs/WiFi-Pumpkin/)
![version](https://img.shields.io/badge/version-0.8.8-orange.svg)

WiFi-Pumpkin - 恶意Wi-Fi接入点攻击框架

### 介绍

WiFi-Pumpkin 是一个恶意的AP框架，可以轻松创建伪造网络，同时转发不知情目标的合法流量.它提供了各种功能，包括恶意Wi-Fi接入点、对客户端AP的deauth攻击、探测器请求和凭据监视器、透明代理、Windows更新攻击、网络钓鱼管理器、ARP中毒、DNS欺骗、Pumpkin代理和动态图像捕获。此外，WiFi-Pumpkin是一个非常完整的Wi-Fi安全审核框架，功能列表非常广泛。

![screenshot](https://raw.githubusercontent.com/P0cL4bs/WiFi-Pumpkin/master/docs/screenshot.png)

### 安装

- Python 2.7

```sh
 git clone https://github.com/P0cL4bs/WiFi-Pumpkin.git
 cd WiFi-Pumpkin
 ./installer.sh --install
```

or 下载 [.deb](https://github.com/P0cL4bs/WiFi-Pumpkin/releases) file to install

```sh
sudo dpkg -i wifi-pumpkin-0.8.8-all.deb
sudo apt-get -f install # force install dependencies if not install normally

```

refer to the wiki for [Installation](https://github.com/P0cL4bs/WiFi-Pumpkin/wiki/Installation)

### 功能

- Rogue Wi-Fi Access Point   恶意Wi-Fi接入点
- Deauth Attack Clients AP   对客户端AP的deauth攻击
- Probe Request Monitor      探测器请求
- DHCP Starvation Attack     DHCP饥饿攻击
- Credentials Monitor        凭据监视
- Transparent Proxy          透明代理
- Windows Update Attack      Windows更新攻击
- Phishing Manager           网络钓鱼管理器
- Partial Bypass HSTS protocol 部分旁路HSTS协议
- Support beef hook
- ARP Poison                 ARP中毒  
- DNS Spoof                  DNS欺骗
- Patch Binaries via MITM (BDF-Proxy) 通过 MITM 修补二进制文件
- LLMNR, NBT-NS and MDNS poisoner (Responder)
- Pumpkin-Proxy (ProxyServer (mitmproxy API))  Pumpkin代理
- Capture images on the fly  动态图像捕获
- TCP-Proxy (with [scapy](http://www.secdev.org/projects/scapy/)) TCP代理
- Moduled plugins and proxys 模块化插件和代理
- Wireless Mode support hostapd-mana/hostapd-karma attacks 无线模式支持hostapd-mana/hostapd-karma攻击
- Capitve-portals [new]

### Donation

##### paypal:

[![donate](https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=PUPJEGHLJPFQL)

##### Via BTC:

1HBXz6XX3LcHqUnaca5HRqq6rPUmA3pf6f

### 插件

| Plugin                                                       | Description                                                                                                                                     |
| :----------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------- |
| [Dns2proxy](https://github.com/LeonardoNve/dns2proxy)        | This tools offer a different features for post-explotation once you change the DNS server to a Victim.                                          |
| [Sstrip2](https://github.com/LeonardoNve/sslstrip2)          | Sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping attacks based version fork @LeonardoNve/@xtr4nge.                     |
| [Sergio_proxy](https://github.com/supernothing/sergio-proxy) | Sergio Proxy (a Super Effective Recorder of Gathered Inputs and Outputs) is an HTTP proxy that was written in Python for the Twisted framework. |
| [BDFProxy](https://github.com/davinerd/BDFProxy-ng)          | Patch Binaries via MITM: BackdoorFactory + mitmProxy, bdfproxy-ng is a fork and review of the original BDFProxy @secretsquirrel.                |
| [Responder](https://github.com/lgandx/Responder)             | Responder an LLMNR, NBT-NS and MDNS poisoner. Author: Laurent Gaffie                                                                            |
| [PumpkinProxy]()                                             | Intercepting HTTP data, this proxy server that allows to intercept requests and response on the fly
| [CaptivePortals]()                                          | Captive-Portal allow the Attacker block Internet access for users until they open the page login page where a password is required before being allowed to browse the web. | 

### 透明代理

![proxy](https://raw.githubusercontent.com/P0cL4bs/WiFi-Pumpkin/master/docs/proxyscenario.png)

透明代理（mitmproxy），可用于拦截和操作http流量修改请求和响应，允许将javascripts注入所访问的目标。您可以很容易地实现一个模块，将数据注入到页面中，在目录“plugins/extension/”中创建一个python文件，该目录将自动列在pumpkin proxy选项卡上。

#### 插件开发例子

```python
from mitmproxy.models import decoded # for decode content html
from plugins.extension.plugin import PluginTemplate

class Nameplugin(PluginTemplate):
   meta = {
       'Name'      : 'Nameplugin',
       'Version'   : '1.0',
       'Description' : 'Brief description of the new plugin',
       'Author'    : 'by dev'
   }
   def __init__(self):
       for key,value in self.meta.items():
           self.__dict__[key] = value
       # if you want set arguments check refer wiki more info.
       self.ConfigParser = False # No require arguments

   def request(self, flow):
       print flow.__dict__
       print flow.request.__dict__
       print flow.request.headers.__dict__ # request headers
       host = flow.request.pretty_host # get domain on the fly requests
       versionH = flow.request.http_version # get http version

       # get redirect domains example
       # pretty_host takes the "Host" header of the request into account,
       if flow.request.pretty_host == "example.org":
           flow.request.host = "mitmproxy.org"

       # get all request Header example
       self.send_output.emit("\n[{}][HTTP REQUEST HEADERS]".format(self.Name))
       for name, valur in flow.request.headers.iteritems():
           self.send_output.emit('{}: {}'.format(name,valur))

       print flow.request.method # show method request
       # the model printer data
       self.send_output.emit('[NamePlugin]:: this is model for save data logging')

   def response(self, flow):
       print flow.__dict__
       print flow.response.__dict__
       print flow.response.headers.__dict__ #convert headers for python dict
       print flow.response.headers['Content-Type'] # get content type

       #every HTTP response before it is returned to the client
       with decoded(flow.response):
           print flow.response.content # content html
           flow.response.content.replace('</body>','<h1>injected</h1></body>') # replace content tag

       del flow.response.headers["X-XSS-Protection"] # remove protection Header

       flow.response.headers["newheader"] = "foo" # adds a new header
       #and the new header will be added to all responses passing through the proxy
```

#### 关于插件

[plugins](https://github.com/P0cL4bs/WiFi-Pumpkin/wiki/Plugins) on the wiki

### TCP-Proxy Server

可以放在TCP流中间的代理。它使用（[scapy]模块（http://www.secdev.org/projects/scapy/）过滤请求和响应流，并主动修改被iFi-Pumpkin截获的tcp协议的数据包。此插件使用模块来查看或修改截获的数据，这些数据可能是模块最容易实现的，只需在“plugins/analyzers/”上添加自定义模块，就会自动列在tcp proxy选项卡上。


```python
from scapy.all import *
from scapy_http import http # for layer HTTP
from default import PSniffer # base plugin class

class ExamplePlugin(PSniffer):
    _activated     = False
    _instance      = None
    meta = {
        'Name'      : 'Example',
        'Version'   : '1.0',
        'Description' : 'Brief description of the new plugin',
        'Author'    : 'your name',
    }
    def __init__(self):
        for key,value in self.meta.items():
            self.__dict__[key] = value

    @staticmethod
    def getInstance():
        if ExamplePlugin._instance is None:
            ExamplePlugin._instance = ExamplePlugin()
        return ExamplePlugin._instance

    def filterPackets(self,pkt): # (pkt) object in order to modify the data on the fly
        if pkt.haslayer(http.HTTPRequest): # filter only http request

            http_layer = pkt.getlayer(http.HTTPRequest) # get http fields as dict type
            ip_layer = pkt.getlayer(IP)# get ip headers fields as dict type

            print http_layer.fields['Method'] # show method http request
            # show all item in Header request http
            for item in http_layer.fields['Headers']:
                print('{} : {}'.format(item,http_layer.fields['Headers'][item]))

            print ip_layer.fields['src'] # show source ip address
            print ip_layer.fields['dst'] # show destiny ip address

            print http_layer # show item type dict
            print ip_layer # show item type dict

            return self.output.emit({'name_module':'send output to tab TCP-Proxy'})

```

#### 关于TCP代理

[TCP-Proxy](https://github.com/P0cL4bs/WiFi-Pumpkin/wiki/TCP-PProxy) on the wiki

#### 关于捕获接口

插件捕获接口允许攻击者构建无线访问点，该访问点与Web服务器和iptables流量捕获规则结合使用以创建钓鱼门户。用户可以在没有密码的情况下自由连接到这些网络，并且通常会被引导到登录页面，在该页面中，在允许浏览Web之前需要密码。

[Captive-portals](https://github.com/mh4x0f/captiveportals) on the wiki

### 截图

[Screenshot](https://github.com/P0cL4bs/WiFi-Pumpkin/wiki/Screenshots) on the wiki

### FAQ

[FAQ](https://github.com/P0cL4bs/WiFi-Pumpkin/wiki/FAQ) on the wiki

### 联系我们

Whether you want to report a [bug](https://github.com/P0cL4bs/WiFi-Pumpkin/issues/new), send a patch or give some suggestions on this project, drop us or open [pull requests](https://github.com/P0cL4bs/WiFi-Pumpkin/pulls)

### 社区
https://discord.gg/jywYskR
