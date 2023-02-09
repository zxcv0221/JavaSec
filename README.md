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
....
### Nday分析
#### CC链
- 推荐白日梦组长的视频
- [算是随堂笔记吧...](https://github.com/zxcv0221/JavaSec/tree/main/Nday%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90)
- https://github.com/frohoff/ysoserial

#### FastJson

[漏洞基础分析](https://github.com/zxcv0221/JavaSec/blob/main/Nday%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/FastJson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/FastJson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90.md)

[1.2.25-1.2.47分析](https://github.com/zxcv0221/JavaSec/blob/main/Nday%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/FastJson%E5%90%84%E7%89%88%E6%9C%AC%E8%A1%A5%E4%B8%81%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/FastJson%E5%90%84%E7%89%88%E6%9C%AC%E8%A1%A5%E4%B8%81%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90.md)

1.2.47之后的版本暂时看不进去了.....后面再说吧

### 代码审计（OWASP TOP 10）& CodeQL
结合CodeQL一块学习，学习每一个漏洞，都要知道哪里最可能会存在这种漏洞，怎么利用CodeQL发现漏洞

#### OWASP TOP 10
- [SQL注入](https://github.com/zxcv0221/JavaSec/tree/main/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E/SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E)
- [XSS](https://github.com/zxcv0221/JavaSec/tree/main/%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E/XSS%E6%BC%8F%E6%B4%9E)
#### CodeQL

看了很多有记录的项目，大多存了很多学习链接，比较懒就直接把那些项目贴过来了。

官方：.....

其他：

https://github.com/Firebasky/CodeqlLearn

https://github.com/ice-doom/CodeQLRule

https://github.com/safe6Sec/CodeqlNote

[优质博客](https://blog.gm7.org/%E4%B8%AA%E4%BA%BA%E7%9F%A5%E8%AF%86%E5%BA%93/02.%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1/03.codeql/01.codeql%E5%85%A5%E9%97%A8.html)

http://tttang.com/archive/1322

......

### 内存马

[Filter型](https://github.com/zxcv0221/JavaSec/blob/main/%E5%86%85%E5%AD%98%E9%A9%AC/Tomcat/%E4%BB%8ETomcat%E5%9F%BA%E7%A1%80%E5%88%B0Filter%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC/%E4%BB%8ETomcat%E5%9F%BA%E7%A1%80%E5%88%B0Filter%E5%9E%8B%E5%86%85%E5%AD%98%E9%A9%AC.md)

[结合CC11反序列化漏洞实现无文件落地注入内存马【Filter型】](https://github.com/zxcv0221/JavaSec/blob/main/%E5%86%85%E5%AD%98%E9%A9%AC/Tomcat/%E7%BB%93%E5%90%88CC11%E5%AE%9E%E7%8E%B0%E6%97%A0%E6%96%87%E4%BB%B6%E8%90%BD%E5%9C%B0%E5%86%85%E5%AD%98%E9%A9%AC%E6%B3%A8%E5%85%A5/%E7%BB%93%E5%90%88CC11%E5%AE%9E%E7%8E%B0%E6%97%A0%E6%96%87%E4%BB%B6%E8%90%BD%E5%9C%B0%E5%86%85%E5%AD%98%E9%A9%AC%E6%B3%A8%E5%85%A5.md)

........

## 文章旁白

......

## 注意
学习的时候参考路线和知识点，不要照抄师傅们的文章，没有意义，还是要在师傅们的总结中自己进行总结。
