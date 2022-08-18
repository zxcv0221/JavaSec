## **学习过程中遇到的tips**

### 部分class文件无法查看源码

在openjdk中下载对应的更新包。

比如：jdk-8u65版本，下载了https://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/af660750b2f4
下载后，操作就是将压缩包中的-->   src\share\classes文件夹下的sun文件夹整个复制一份到jdk的src中

![img](img/1.png)
先解压jdk自带的src压缩包，然后将sun文件夹粘贴到src文件夹中

![img](img/2.png)

然后就可以回到IDEA中进行设置了

Ctrl+Alt+Shift+S 

选择SDKs，然后点击对应的jdk，选择Sourcepath，把src文件夹加入其中，最后apply即可。

![img](img/3.png)

然后就结束了。可以看到那些class的源码了。

## 