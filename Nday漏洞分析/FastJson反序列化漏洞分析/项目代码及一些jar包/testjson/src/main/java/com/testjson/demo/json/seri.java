package com.testjson.demo.json;


import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class seri {
    public static void main(String[] args) {
//        User user = new User();
//        user.setUsername("777");
//        user.setPassword("admin777");
        Student student = new Student();
        student.setAge(80);
        student.setName("777");

        String testjson = JSON.toJSONString(student, SerializerFeature.WriteClassName);

        System.out.println(testjson);
    }
}
