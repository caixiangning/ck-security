package org.codethink.messagedigest;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * 消息摘要算法之SHA算法测试类
 * 
 * @author CaiXiangNing
 * @date 2016年12月12日
 * @email caixiangning@gmail.com
 */
public class SHACoderTest {
	
	private static final Logger logger = LoggerFactory.getLogger(SHACoderTest.class);
	
	/**
	 * 测试SHA-1消息摘要算法
	 * @throws Exception
	 */
	@Test
	public final void testEncodeSHA1() throws Exception{
		String str = "SHA-1 消息摘要";
		// 获得摘要信息
		byte[] data1 = SHACoder.encodeSHA1(str.getBytes());
		byte[] data2 = SHACoder.encodeSHA1(str.getBytes());
		// 两次摘要校验
		Assert.assertArrayEquals(data1, data2);
		
		logger.info("经过SHA-1加密算法后生成的十六进制字符串密文：{}", Hex.encodeHexString(data1));
		logger.info("经过SHA-1加密算法后生成的十六进制字符串密文：{}", Hex.encodeHexString(data2));
	}
	
	/**
	 * 测试SHA-256消息摘要算法
	 * @throws Exception
	 */
	@Test
	public final void testEncodeSHA256() throws Exception{
		String str = "SHA-256 消息摘要";
		// 获得摘要信息
		byte[] data1 = SHACoder.encodeSHA256(str.getBytes());
		byte[] data2 = SHACoder.encodeSHA256(str.getBytes());
		// 两次摘要校验
		Assert.assertArrayEquals(data1, data2);
		
		logger.info("经过SHA-256加密算法后生成的十六进制字符串密文：{}", Hex.encodeHexString(data1));
		logger.info("经过SHA-256加密算法后生成的十六进制字符串密文：{}", Hex.encodeHexString(data2));
	}
}

