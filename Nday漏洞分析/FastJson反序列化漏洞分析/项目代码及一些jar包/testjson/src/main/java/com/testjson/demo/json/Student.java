package com.testjson.demo.json;

import com.alibaba.fastjson.JSON;

import java.io.IOException;
import java.util.jar.JarEntry;

public class Student {
    private String name;
    private int age;
    private String sex;

    public Student() {
        System.out.println("构造函数");
    }

    public String getName() {
        System.out.println("getName");
        return name;
    }

    public void setName(String name) {
        System.out.println("setName");
        this.name = name;
    }

    public int getAge() {
        System.out.println("getAge");
        return age;
    }

    public void setAge(int age) {
        System.out.println("setAge");
        this.age = age;
    }
    public void setSex(String sex) throws IOException {
        System.out.println("setSex");
        Runtime.getRuntime().exec("calc.exe");
    }
}

