package com.nano.common.utils;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;

/**
 * 网络工具类
 *
 * @author Vinicolor
 * @version V1.0
 * @date 2018/11/12 20:22
 * @email vinicolor.violet.end@gmail.com
 * Description:
 * 网络工具
 */
public class NetworkUtils {

    public static String getHardwareAddress() {
        InetAddress ip;
        try {
            ip = InetAddress.getLocalHost();
            NetworkInterface network = NetworkInterface.getByInetAddress(ip);
            byte[] mac = network.getHardwareAddress();
            StringBuilder sb = new StringBuilder();
            for (byte macByte : mac) {
                sb.append(String.format("%02x", macByte));
            }
            return sb.toString();
        } catch (UnknownHostException | SocketException e) {
            e.printStackTrace();
        }
        return null;
    }

}
