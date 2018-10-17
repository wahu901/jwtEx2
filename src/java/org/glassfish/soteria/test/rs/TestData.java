/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.glassfish.soteria.test.rs;

/**
 *
 * @author Peter.pan
 */
public class TestData {
    private String param1;
    private String param2;

    public TestData(){}
    public TestData(String param1, String param2){
        this.param1 = param1;
        this.param2 = param2;
    }
    
    public String getParam1() {
        return param1;
    }

    public void setParam1(String param1) {
        this.param1 = param1;
    }

    public String getParam2() {
        return param2;
    }

    public void setParam2(String param2) {
        this.param2 = param2;
    }
}
