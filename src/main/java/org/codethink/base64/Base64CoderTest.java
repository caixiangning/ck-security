package org.codethink.base64;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Base64算法测试类
 * 
 * @author CaiXiangNing
 * @date 2016年12月12日
 * @email caixiangning@gmail.com
 */
public class Base64CoderTest {
	
	private static final Logger logger = LoggerFactory.getLogger(Base64CoderTest.class);
	
	@Test
	public void testBase64Coder(){
		String inputStr = "Java加密与解密的艺术";
		logger.info("未经过任何处理的明文：{} ", inputStr);
		// 进行Base64编码
		String code = Base64Coder.encode(inputStr);
		logger.info("使用Base64算法进行编码操作后的文本字符串形式的结果： {}", code);
		// 进行Base64解码
		String outputStr = Base64Coder.decode(code);
		logger.info("使用Base64算法进行解码操作后的文本字符串形式的结果：{}", outputStr);
		// 验证Base64编码解码一致性
		Assert.assertEquals(inputStr, outputStr);
	}
}

