<a href="https://gitmoji.dev">
  <img src="https://img.shields.io/badge/gitmoji-%20😜%20😍-FFDD67.svg?style=flat-square" alt="Gitmoji">
</a>

# JavaSec

## 学习参考
1. 知识星球
2. https://github.com/DuGuQiuBai/Java
3. https://github.com/Y4tacker/JavaSec
4. 小破站UP：[白日梦组长](https://space.bilibili.com/2142877265)
5. https://github.com/Drun1baby/JavaSecurityLearning
6. Google&&Baidu

## 路线
### Java基础
1. Java反射部分，我写的比较粗略，学习推荐从开发的角度去学，推荐这个：[小破站视频](https://www.bilibili.com/video/BV1C4411373T)
2. 静态代理和动态代理
3. 类加载机制（....自定义类加载器..）
4. Java反序列化
5. javassist
6. JNDI&RMI....
7. URLDNS利用链
8. ....
### Nday分析
#### CC链
- 推荐白日梦组长的视频
- [算是随堂笔记吧...](https://github.com/zxcv0221/JavaSec/tree/main/Nday%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/Commons-Collections)
- https://github.com/frohoff/ysoserial

#### FastJson

[FastJson反序列化漏洞分析](https://github.com/zxcv0221/JavaSec/blob/main/Nday%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/FastJson/FastJson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/FastJson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90.md)

[FastJson各版本补丁绕过](https://github.com/zxcv0221/JavaSec/blob/main/Nday%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/FastJson/FastJson%E5%90%84%E7%89%88%E6%9C%AC%E8%A1%A5%E4%B8%81%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/FastJson%E5%90%84%E7%89%88%E6%9C%AC%E8%A1%A5%E4%B8%81%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90.md)

[FastJson不出网利用BCEL分析](https://github.com/zxcv0221/JavaSec/blob/main/Nday%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/FastJson/FastJson%E4%B8%8D%E5%87%BA%E7%BD%91%E5%88%A9%E7%94%A8BCEL%E5%88%86%E6%9E%90/FastJson%E4%B8%8D%E5%87%BA%E7%BD%91%E5%88%A9%E7%94%A8BCEL%E5%88%86%E6%9E%90.md)



### 代码审计（OWASP TOP 10）& CodeQL
结合CodeQL一块学习，学习每一个漏洞，都要知道哪里最可能会存在这种漏洞，怎么利用CodeQL发现漏洞

#### OWASP TOP 10
- [SQL注入](https://github.com/zxcv0221/JavaSec/tree/main/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E/SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E)
- [XSS](https://github.com/zxcv0221/JavaSec/tree/main/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E/XSS%E6%BC%8F%E6%B4%9E)
#### CodeQL

看了很多有记录的项目，记录下一些比较好的学习项目

|                      项目地址                       | 项目描述                                                     |
| :-------------------------------------------------: | ------------------------------------------------------------ |
|       https://github.com/j3ssie/codeql-docker       | 可以docker搭建codeql环境，结合[extractor-java](https://github.com/waderwu/extractor-java)项目使用 |
|      https://github.com/waderwu/extractor-java      | 分析闭源Jar包，且生成database比较方便                        |
|  https://github.com/github/securitylab/discussions  | 有关codeql的问题，可以在官方的discussions这里提问            |
|    https://github.com/SummerSec/LookupInterface     | CodeQL 寻找 JNDI利用 Lookup接口                              |
|      https://github.com/zbazztian/codeql-debug      | CodeQL Debug Action                                          |
|    https://github.com/SummerSec/learning-codeql     | CodeQL Java 全网最全的中文学习资料                           |
|      https://github.com/zbazztian/codeql-tools      | 分析闭源Java程序                                             |
| https://github.com/advanced-security/codeql-queries | 自定义CodeQL查询                                             |
|          https://github.com/ASTTeam/CodeQL          | 深入理解CodeQL                                               |
|          https://github.com/github/codeql           | 官方                                                         |
|   https://github.com/github/vscode-codeql-starter   | 官方：VScode快速开始项目                                     |
|        https://github.com/webraybtl/CodeQLpy        | 半自动化审计【还没用过】                                     |
|       https://github.com/ice-doom/CodeQLRule        | SpringMVC路由收集                                            |
|          https://github.com/cor0ps/codeql           | 收集规则                                                     |

还有很多，等用/遇到其他的优质项目再加入

......

### 内存马

[Filter型](https://github.com/zxcv0221/JavaSec/blob/main/%E5%86%85%E5%AD%98%E9%A9%AC/Tomcat/%E4%BB%8ETomcat%E5%9F%BA%E7%A1%80%E5%88%B0Filter%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/%E4%BB%8ETomcat%E5%9F%BA%E7%A1%80%E5%88%B0Filter%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC.md)

[结合CC11反序列化漏洞实现无文件落地注入内存马【Filter型】](https://github.com/zxcv0221/JavaSec/blob/main/%E5%86%85%E5%AD%98%E9%A9%AC/Tomcat/%E7%BB%93%E5%90%88CC11%E5%AE%9E%E7%8E%B0%E6%97%A0%E6%96%87%E4%BB%B6%E8%90%BD%E5%9C%B0%E5%86%85%E5%AD%98%E9%A9%AC%E6%B3%A8%E5%85%A5/%E7%BB%93%E5%90%88CC11%E5%AE%9E%E7%8E%B0%E6%97%A0%E6%96%87%E4%BB%B6%E8%90%BD%E5%9C%B0%E5%86%85%E5%AD%98%E9%A9%AC%E6%B3%A8%E5%85%A5.md)

[Listen型](https://github.com/zxcv0221/JavaSec/blob/main/%E5%86%85%E5%AD%98%E9%A9%AC/Tomcat/Listen%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/Listen%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC.md)

........

## 文章旁白

......

## 注意
学习的时候参考路线和知识点，不要照抄师傅们的文章，没有意义，还是要在师傅们的总结中自己进行总结。
