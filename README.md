# School-Year-Design
 This is my work. From 2017.3.26 to Now.

### 分支说明
  1. master：主分支，一周会更新一次
  2. sking_modify：我自己的分支，每天只要学习了就会更新一次

### 文件说明（笔记里的链接可能无法使用，因为我只导出了关键笔记）
  1. Document：网上搜集的关于课程的文档资料
  2. OneNote：我的OneNote笔记
      - 学年设计--WiFi安全.one
      - Wireshark.one
      - Python基础.one

-----------------------------

> ## 第4周(2017.3.20-2017.3.26)
> > ### 2017.3.26   
> > 1. 创建了一个学年设计的Github Repository，并git clone到了本地
> > 2. 下载了Atom编辑器，并简单的查看了Markdown的语法
> > 3. 创建了OneNote笔记库，用于资料的备份
> > 4. 搜集了关于Wi-Fi加密方式的文档：WEP/WPA/WPA2
> > 5. 搜集了路由器WPS的漏洞机制相关文档
> > 6. 对无线钓鱼AP有了一定的了解，并明确了实现目标
>
>
>
> ## 第5周(2017.3.27-2017.4.2)
> > ### 2017.3.27
> > 1. 学会了wireshark的简单实用方法   
> >   1.1 Filter的使用方法  
> >   1.2 IO Graph、RTT Graph、Flow Graph图形显示观察数据  
> >   1.3 使用TCP Stream跟踪数据流  
> >   1.4 简单的Expert Info信息解读，对异常数据包判断  
> >   1.5 学会tshark的简单实用，使用命令行对数据包进行解析  
> >  
> > 2. 对各种协议进行报文格式的解读和抓包分析  
> >   2.1 ARP报文   
> >   2.2 IPv4报文、IP分片抓包  
> >   2.3 TCP报文、TCP三次握手 、TCP序列/确认机制 、滑动窗口、 Keepalive、重传、快速重传  
> >   2.4 ICMP报文、ping包、tracert包  
> >   2.5 DHCP报文(release/discover/offer/request/ack)  
> >   2.6 DNS报文、查询报文、递归查询报文、区域传送报文  
>
> > ### 2017.3.28-2017.4.1
> > 1. 继续对各种协议进行抓包分析  
> >   1.1 HTTP报文、HTTP的工作流程、HTTP Request/Response、HTTP的请求方法和相关状态码、HTTP的数据压缩格式  
> >   1.2 HTTPS报文、SSL的加密方式、SSL的传输过程、TLS Handshaking Protocols、TLS Record Layer Protocol  
> >   1.3 FTP报文、传输模式、Windows cmd下的FTP命令、明文传输解密  
> >   1.4 NFS报文、NFS的mount操作、NFS的Read/Write过程分析  
> >   1.5 E-mail报文、SMTP、POP/POP3、IMAP、数据包的解密  
> >   1.6 802.11报文  
> > 2. 对某些常见的上网错误信息，学会了使用wireshark进行简单排错搭建技能  
> > 3. 了解了一些漏洞原理：SYN扫描、嗅探器使用、ARP欺骗、网络钓鱼攻击案例  
>
> > ### 2017.4.2-4.3
> > 1. 回顾了python的基本语法，并记入了笔记
> > 2. python的正则表达式，多线程，简单web编程进行了学习
> > 3. 完成Python的[爬虫闯关游戏](“http://www.heibanke.com/lesson/crawler_ex00/”)
>
>
> ## 第6-10周（2017.4.4-2017.5.6）
> > 不要问我干了什么，啥都没干  
> > 无理由旷工    
> > 从下一周开始继续工作(#愤怒)  
>
> ## 第11-12周（2017.5.7-5.21）  
> > 1. 看了《网络安全基础》这本书，了解了对称和非对称加密，及其应用场景  
> > 2. 重点学了了WiFi加密中的WEP加密：RC4算法  
> > 3. 学习了简单的SQL注入（好像跟我的学年设计没什么关系）  
> > 4. 用Pythons实现了了哔哩哔哩所有用户的爬虫，放在了[github](https://github.com/swusking/Bilibili_users)上  
>
> ## 第13周（2017.5.22-28）
> > ### 2017.5.22-2017.24
> > 1. 在Windows下安装了Python-scapy模块，遇到了很大的坑，记录到了[博客](http://www.skingyang.cn/wordpress/267.html)  
> > 2. 学习使用了scapy模块的抓底层的包，觉得Windows下坑太大太大，我已无法装填，所以我将直接在虚拟机里装Kali Linux来进行操作，环境都要重新搭建  
> > 3. 找了关于WEP加密的学习资料，放入了Document  
> > 4.  H3C要复赛了，我却不慌不忙。看来我要去复习复习了    
