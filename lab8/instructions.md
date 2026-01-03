网络结束与应用第八次实验
实验名称：PPPoE服务器的配置和应用
王泽舜 学号2310655
一、实验要求
PPPoE服务器配置和应用实验在虚拟仿真环境下完成，要求如下：
1.仿真有线局域网接入互联网的场景，正确配置PPPoE服务器的认证协议、地址池、虚拟模板和物理接口，使内网用户经认证后才能正常访问外部互联网。
2.仿真家庭网络中，无线和有线终端（主机、智能电话等）连入小型路由器，由小型路由器统一接入互联网服务运营商PPPoE服务器的场景。对小型路由器和PPPoE服务器进行设置，使家庭网络中的用户经认证后才能正常访问外部互联网。
实验1：
网络拓扑见pictures\网络拓扑.png，server3做aaa认证，router2是ISP，router3连接的192.168.3.0网段的内网模拟外网
server3配置：见pictures\AAAServer网络和账号配置.png
router2配置：
aaa new-model
aaa authentication ppp myPPPoE group radius
radius-server host 192.168.2.3 auth-port 1645 key radius123
ip local pool myPool 192.168.1.100 192.168.1.200
interface virtual-template 1
ip unnumber gig0/1
peer default ip address pool myPool
ppp authentication chap myPPPoE
exit
bba-group pppoe myBBAGroup
virtual-template 1
exit
interface gig0/1
pppoe enable group myBBAGroup
exit
