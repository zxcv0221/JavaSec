package com.testjson.demo.json;

import com.alibaba.fastjson.JSON;

public class Unser {
    public static void main(String[] args){
        String jsonstring ="{\"@type\":\"com.testjson.demo.json.Student\":\"age\":80,\"name\":\"777\",\"sex\":\"man\"}";
        //System.out.println(JSON.parse(jsonstring));
        System.out.println(JSON.parseObject(jsonstring));
    }
}
