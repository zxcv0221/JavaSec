package com.testjson.demo.json;

public class User {
    private String username;
    private String password;

    public User() {
        System.out.println("构造函数");
    }

    public String getUsername() {
        System.out.println("getUsername");
        return username;
    }

    public void setUsername(String username) {
        System.out.println("setUsername");
        this.username = username;
    }

    public String getPassword() {
        System.out.println("getPassword");
        return password;
    }

    public void setPassword(String password) {
        System.out.println("setPassword");
        this.password = password;
    }
}