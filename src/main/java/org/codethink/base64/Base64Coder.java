package org.codethink.base64;

import org.apache.commons.codec.binary.Base64;
/**
 * 
 * Base64算法实现
 * 
 * @author CaiXiangNing
 * @date 2016年12月12日
 * @email caixiangning@gmail.com
 * 附：抽象类不能实例化，但是仍然可以通过类调用静态方法还能防止实例化(不错的思路)
 */
public abstract class Base64Coder {
	
	/**
	 * Base64编码
	 * @param data 待编码的数据
	 * @return
	 */
	public static String encode(String data){
		byte[] encodeBytes = Base64.encodeBase64(data.getBytes());
		return new String(encodeBytes);
	}
	
	/**
	 * Base64解码
	 * @param data 待解码的数据
	 * @return
	 */
	public static String decode(String data){
		byte[] decodeBytes = Base64.decodeBase64(data.getBytes());
		return new String(decodeBytes);
	}
}

