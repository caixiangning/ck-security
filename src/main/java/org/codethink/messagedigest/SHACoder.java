package org.codethink.messagedigest;

import java.security.MessageDigest;

/**
 * 
 * 消息摘要算法之SHA算法实现类
 * 
 * 消息摘要算法SHA的实现也是通过MessageDigest类来完成的。
 * Java6支持SHA-1、SHA-256、SHA-384、SHA-512的算法实现。
 * 第三方加密组件包Bouncy Castle支持SHA-224算法。
 * 附：抽象类不能实例化，但是仍然可以通过类调用静态方法还能防止实例化(不错的思路)
 * 
 * @author CaiXiangNing
 * @date 2016年12月11日
 * @email caixiangning@gmail.com
 */
public abstract class SHACoder {
	
	/**
	 * SHA或者SHA-1消息摘要
	 * @param data 待做消息摘要处理的数据
	 * @return 经过摘要处理后的摘要信息，即数字指纹
	 * @throws Exception
	 */
	public static byte[] encodeSHA1(byte[] data) throws Exception{
		// 初始化MessageDigest，并指定SHA-1算法
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		// 进行摘要处理，digest方法的参数是待做消息摘要处理的数据，返回值是经过摘要处理后的摘要信息，即数字指纹
		return md.digest(data);
	}
	
	/**
	 * SHA-256消息摘要
	 * @param data 待做消息摘要处理的数据
	 * @return 经过摘要处理后的摘要信息，即数字指纹
	 * @throws Exception
	 */
	public static byte[] encodeSHA256(byte[] data) throws Exception{
		// 初始化MessageDigest，并指定SHA-256算法
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		// 进行摘要处理，digest方法的参数是待做消息摘要处理的数据，返回值是经过摘要处理后的摘要信息，即数字指纹
		return md.digest(data);
	}
}

