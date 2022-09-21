package com.testjson.demo.json;

import com.alibaba.fastjson.JSON;

public class unseri {
    public static void main(String[] args) {
        //String testjson = "{\"@type\":\"com.testjson.demo.json.User\",\"password\":\"admin777\",\"username\":\"777\"}";
        String testjson = "{\"password\":\"admin777\",\"username\":\"777\"}";
        System.out.println(JSON.parse(testjson));
        System.out.println(JSON.parseObject(testjson));
        System.out.println(JSON.parseObject(testjson, User.class));
    }
}
