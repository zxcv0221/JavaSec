package test;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.util.Base64;
import java.util.Base64.Encoder;
/*
 * 加密class文件
 */
public class HelloWorld {
    public static void main(String args[]) {
        byte[] buffer = null;
        //获取当前路径，这里是java工程路径
        String str = System.getProperty("user.dir");
        System.out.println(str);
        String filepath = ".\\src\\main\\java\\test\\EvilClass.class";
        try {
            FileInputStream fis = new FileInputStream(filepath);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] b = new byte[1024];
            int n;
            while((n = fis.read(b))!=-1) {
                bos.write(b,0,n);
            }
            fis.close();
            bos.close();
            buffer = bos.toByteArray();
        }catch(Exception e) {
            e.printStackTrace();
        }
        Encoder encoder = Base64.getEncoder();
        String value = encoder.encodeToString(buffer);
        System.out.println(value);
        System.out.println("HelloWorld");
    }
}