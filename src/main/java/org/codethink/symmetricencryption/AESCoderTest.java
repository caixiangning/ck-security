package org.codethink.symmetricencryption;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * 对称加密算法之AES算法测试类
 * 
 * @author CaiXiangNing
 * @date 2016年12月12日
 * @email caixiangning@gmail.com
 */
public class AESCoderTest {
	
	private static final Logger logger = LoggerFactory.getLogger(AESCoderTest.class);
	
	/**
	 * 测试AES加密解密算法
	 * 
	 * @throws Exception
	 */
	@Test
	public void testAES() throws Exception {
		String inputStr = "AES 加密算法";
		logger.info("未经过任何处理的明文：{} ", inputStr);
		// 生成密钥
		byte[] keyByte = AESCoder.generateSecretKey();
		logger.info("使用密钥生成器生成的十六进制形式的密钥： {}", Hex.encodeHexString(keyByte));
		// 执行加密操作
		byte[] encryptByte = AESCoder.encrypt(inputStr.getBytes(), keyByte);
		logger.info("经过AES加密算法加密后生成的十六进制密文：{}",Hex.encodeHexString(encryptByte));
		// 执行解密操作
		// 理解十六进制字符串和文本字符串的区别：前者是4位表示一个字符，后者是16位表示一个字符
		byte[] decryptByte = AESCoder.decrypt(encryptByte, keyByte);
		logger.info("经过AES加密算法解密后生成的十六进制形式的解密文：{}", Hex.encodeHexString(decryptByte));
		logger.info("经过AES加密算法解密后生成的文本字符串形式的解密文：{}", new String(decryptByte));

		Assert.assertEquals(inputStr, new String(decryptByte));
	}
}

