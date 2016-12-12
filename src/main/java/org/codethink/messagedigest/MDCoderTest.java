package org.codethink.messagedigest;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * 消息摘要算法之MD算法测试类
 * 
 * @author CaiXiangNing
 * @date 2016年12月12日
 * @email caixiangning@gmail.com
 */
public class MDCoderTest {
	
	private static final Logger logger = LoggerFactory.getLogger(MDCoderTest.class);
	
	/**
	 * 测试MD2消息摘要算法
	 * @throws Exception
	 */
	@Test
	public final void testEncodeMD2() throws Exception{
		String str = "MD2 消息摘要";
		// 获得摘要信息
		byte[] data1 = MDCoder.encodeMD2(str.getBytes());
		byte[] data2 = MDCoder.encodeMD2(str.getBytes());
		// 两次摘要校验，摘要值是相同的
		Assert.assertArrayEquals(data1, data2);
		
		logger.info("经过MD2加密算法后生成的十六进制字符串密文：{}", Hex.encodeHexString(data1));
		logger.info("经过MD2加密算法后生成的十六进制字符串密文：{}", Hex.encodeHexString(data2));
	}
	
	/**
	 * 测试MD5消息摘要算法
	 * @throws Exception
	 */
	@Test
	public final void testEncodeMD5() throws Exception{
		String str = "MD5 消息摘要";
		// 获得摘要信息
		byte[] data1 = MDCoder.encodeMD5(str.getBytes());
		byte[] data2 = MDCoder.encodeMD5(str.getBytes());
		// 两次摘要校验，摘要值是相同的
		Assert.assertArrayEquals(data1, data2);
		
		logger.info("经过MD5加密算法后生成的十六进制字符串密文：{}", Hex.encodeHexString(data1));
		logger.info("经过MD5加密算法后生成的十六进制字符串密文：{}", Hex.encodeHexString(data2));
	}
}

