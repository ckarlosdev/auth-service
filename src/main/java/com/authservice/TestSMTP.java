package com.authservice;

import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class TestSMTP {
    public static void main(String[] args) throws UnknownHostException {
        InetAddress address = InetAddress.getByName("smtp.gmail.com");
        System.out.println("IP de smtp.gmail.com: " + address.getHostAddress());
    }
}
