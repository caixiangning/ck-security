package org.codethink.messagedigest;

import java.security.MessageDigest;

/**
 * 
 * 消息摘要算法之MD算法实现类
 * 
 * JDK仅仅提供了MD2和MD5的实现，但是Bouncy Castle提供了MD4的实现。
 * MD消息摘要算法都是根据一个随机长度的信息产生一个128位二进制摘要信息。
 * 如果将这个128位的二进制摘要信息换算成十六进制，就可以得到一个32位的字符串
 * （每4位二进制数转换为1位十六进制数）。
 * 附：抽象类不能实例化，但是仍然可以通过类调用静态方法还能防止实例化(不错的思路)
 * 
 * @author CaiXiangNing
 * @date 2016年12月11日
 * @email caixiangning@gmail.com
 */
public abstract class MDCoder {
	
	/**
	 * MD2消息摘要算法
	 * @param data 待做消息摘要处理的数据
	 * @return 经过摘要处理后的摘要信息，即数字指纹
	 * @throws Exception
	 */
	public static byte[] encodeMD2(byte[] data) throws Exception{
		// 初始化MessageDigest，并指定MD2算法
		MessageDigest md2 = MessageDigest.getInstance("MD2");
		// 进行摘要处理，digest方法的参数是待做消息摘要处理的数据，返回值是经过摘要处理后的摘要信息，即数字指纹
		return md2.digest(data);
	}
	
	/**
	 * MD5消息摘要算法
	 * @param data 待做消息摘要处理的数据
	 * @return 经过摘要处理后的摘要信息，即数字指纹
	 * @throws Exception
	 */
	public static byte[] encodeMD5(byte[] data) throws Exception{
		// 初始化MessageDigest，并指定MD2算法
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		// 进行摘要处理，digest方法的参数是待做消息摘要处理的数据，返回值是经过摘要处理后的摘要信息，即数字指纹
		return md5.digest(data);
	}
}

