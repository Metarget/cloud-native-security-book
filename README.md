# 《云原生安全：攻防实践与体系构建》资料仓库

<p align="center">
  <img src="https://raw.githubusercontent.com/brant-ruan/cloud-native-security-book/main/images/book.jpg" width = "250" height = "317" alt="" />
</p>

本仓库提供了《云原生安全：攻防实践与体系构建》一书的补充材料和随书源码，供感兴趣的读者深入阅读、实践。

**本仓库所有内容仅供教学、研究使用，严禁用于非法用途，违者后果自负！**

相关链接：[豆瓣](https://book.douban.com/subject/35640762/) | [京东](https://item.jd.com/13495676.html) | [当当](http://product.dangdang.com/29318802.html)

## 补充阅读资料


- [100_云计算简介.pdf](appendix/100_云计算简介.pdf)
- [101_代码安全.pdf](appendix/101_代码安全.pdf)
- [200_容器技术.pdf](appendix/200_容器技术.pdf)
- [201_容器编排.pdf](appendix/201_容器编排.pdf)
- [202_微服务.pdf](appendix/202_微服务.pdf)
- [203_服务网格.pdf](appendix/203_服务网格.pdf)
- [204_DevOps.pdf](appendix/204_DevOps.pdf)
- [CVE-2017-1002101：突破隔离访问宿主机文件系统.pdf](appendix/CVE-2017-1002101：突破隔离访问宿主机文件系统.pdf)
- [CVE-2018-1002103：远程代码执行与虚拟机逃逸.pdf](appendix/CVE-2018-1002103：远程代码执行与虚拟机逃逸.pdf)
- [CVE-2020-8595：Istio认证绕过.pdf](appendix/CVE-2020-8595：Istio认证绕过.pdf)
- [靶机实验：综合场景下的渗透实战.pdf](appendix/靶机实验：综合场景下的渗透实战.pdf)

## 随书源码

|代码目录|描述|定位|
|:-|:-|:-|
|[0302-开发侧攻击/02-CVE-2018-15664/symlink_race/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0302-开发侧攻击/02-CVE-2018-15664/symlink_race)| CVE-2018-15664漏洞利用代码|3.2.2小节|
|[0302-开发侧攻击/03-CVE-2019-14271/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0302-开发侧攻击/03-CVE-2019-14271)|CVE-2019-14271漏洞利用代码|3.2.3小节|
|[0303-供应链攻击/01-CVE-2019-5021-alpine/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0303-供应链攻击/01-CVE-2019-5021-alpine)|基于存在CVE-2019-5021漏洞的Alpine镜像构建漏洞镜像示例|3.3.1小节|
|[0303-供应链攻击/02-CVE-2016-5195-malicious-image/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0303-供应链攻击/02-CVE-2016-5195-malicious-image)|CVE-2016-5195漏洞利用镜像构建示例|3.3.2小节|
|[0304-运行时攻击/01-容器逃逸/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0304-运行时攻击/01-容器逃逸)|多个用于容器逃逸的代码片段|3.4.1小节|
|[0304-运行时攻击/02-安全容器逃逸/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0304-运行时攻击/02-安全容器逃逸)|安全容器逃逸的漏洞利用代码|3.4.2小节|
|[0304-运行时攻击/03-资源耗尽型攻击/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0304-运行时攻击/03-资源耗尽型攻击)|资源耗尽型攻击示例代码|3.4.3小节|
|[0402-Kubernetes组件不安全配置/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0402-Kubernetes组件不安全配置/)|K8s不安全配置的利用命令|4.2节|
|[0403-CVE-2018-1002105/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0403-CVE-2018-1002105)|CVE-2018-1002105漏洞利用代码|4.3节|
|[0404-K8s拒绝服务攻击/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0404-K8s拒绝服务攻击/)|CVE-2019-11253和CVE-2019-9512的漏洞利用代码|4.4节|
|[0405-云原生网络攻击/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0405-云原生网络攻击/)|云原生中间人攻击网络环境模拟及攻击代码示例|4.5节|

## 分享与交流

欢迎关注“绿盟科技研究通讯”公众号，我们将持续、高质量地输出信息安全前沿领域研究成果：

![微信搜索“绿盟科技研究通讯”](images/yjtx.png)

## 注意事项

其中部分源码来自网络上其他地方，为方便读者实践，一并归档。这些源码及“摘录出处”为：

1. [0302-开发侧攻击/02-CVE-2018-15664/symlink_race](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0302-开发侧攻击/02-CVE-2018-15664/symlink_race)：https://seclists.org/oss-sec/2019/q2/131
2. [0302-开发侧攻击/03-CVE-2019-14271/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0302-开发侧攻击)：https://unit42.paloaltonetworks.com/docker-patched-the-most-severe-copy-vulnerability-to-date-with-cve-2019-14271/
3. [0304-运行时攻击/01-容器逃逸/CVE-2016-5195/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0304-运行时攻击/01-容器逃逸/CVE-2016-5195)：https://github.com/scumjr/dirtycow-vdso
4. [0304-运行时攻击/01-容器逃逸/CVE-2019-5736/](https://github.com/brant-ruan/cloud-native-security-book/tree/main/code/0304-运行时攻击/01-容器逃逸/CVE-2019-5736)：https://github.com/Frichetten/CVE-2019-5736-PoC

引用的项目及代码的许可证（License）以原项目为准。

部分经过笔者修改的源码不再在此列出，书中对相关引用均给出了出处，感兴趣的读者可以参考。

## 勘误及补充说明

### 第1版第3次印刷

#### P42 - 3.2.3 CVE-2019-14271：加载不受信任的动态链接库

详见[issue 6](https://github.com/Metarget/cloud-native-security-book/issues/6)。

感谢读者[@XDTG](https://github.com/XDTG)指出。书上的步骤在效果上没有问题，但@XDTG提出的方案更自然优雅。经验证后，我们考虑在后续的印刷中更新方案。

### 第1版第1次印刷

#### P37 - 3.2.2 CVE-2018-15664：符号链接替换漏洞（这里为补充说明，原文并无错误）

正文第八行开始的段落描述较难理解：

> symlink_swap.c的任务是在容器内创建指向根目录“/”的符号链接，并不断地交换符号链接（由命令行参数传入，如“/totally_safe_path”）与一个正常目录（例如“/totally_safe_path-stashed”）的名字。这样一来，在宿主机上执行 docker cp时，如果首先检查到“/totally_safe_path”是一个正常目录，但在后面执行复制操作时“/totally_safe_path”却变成了一个符号链接，那么Docker将在宿主机上解析这个符号链接。

事实上，在容器内部，一旦开始通过renameat2进行名称交换，`/totally_safe_path`和`/totally_safe_path-stashed`实际上对于我们来说只是两个字符串了，不再与符号链接或正常目录绑定，只有停止交换的那一刻，才会重新确定哪个字符串指向哪个（符号链接或目录）。

因此，书中“这样一来，在宿主机上执行docker cp时，如果首先...”这里，这时，容器内已经开始进行名称交换了。用户（或攻击者）想要去docker cp的是容器内名为`/totally_safe_path`的文件或目录（“十分安全的路径”的意思），这是预期（或者说是这个场景的设定）；docker cp在执行过程中，在检查阶段，`/totally_safe_path`路径字符串还指向一个正常目录，但是到了复制操作时，`/totally_safe_path`却已经被交换指向了一个符号链接。

感谢读者@泡泡球麻麻君指出。

#### P85 - 4.2.1 Kubernetes API Server未授权访问（第1版第3次印刷已修复）

正文倒数第四行部分存在歧义：

> 那么攻击者只要网络可达，都能够通过此端口操控集群。

事实上，如果仅仅设置`--insecure-port=8080`，那么服务也只是监听在`localhost`，远程攻击者通常情况下是无法访问的，即使从IP角度来讲是“网络可达的”。如果想要远程操控，还需要配置`--insecure-bind-address=0.0.0.0`才行。

这里的“网络可达”实际上想说明两种情况：

1. 加`--insecure-bind-address`的情况下直接被外部访问，即上面这种；
2. 能够以某种方式访问到localhost，这个场景又包括：
    1. 本地用户利用8080端口的服务来提升权限；
    2. 基于类似SSRF、DNS rebinding的方式来实现远程访问localhost端口。
