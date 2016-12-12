package org.codethink.asymmetricencryption;

import java.util.Map;

import org.apache.commons.codec.binary.Hex;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * 非对称算法RSA算法测试类
 * 
 * @author CaiXiangNing
 * @date 2016年12月11日
 * @email caixiangning@gmail.com
 */
public class RSACoderTest {
	
	private static final Logger logger = LoggerFactory.getLogger(RSACoderTest.class);
	// 公钥
	private byte[] publicKey;
	// 私钥
	private byte[] privateKey;

	/**
	 * 准备：构建发送方密钥对(公钥和私钥)
	 * 
	 * @throws Exception
	 */
	@Before
	public void generateKey() throws Exception {
		Map<String, Object> keyMap = RSACoder.generateKey();
		publicKey = RSACoder.getPublicKey(keyMap);
		privateKey = RSACoder.getPrivateKey(keyMap);
		logger.info("使用密钥生成器生成的十六进制形式的公钥：{}", Hex.encodeHexString(publicKey));
		logger.info("使用密钥生成器生成的十六进制形式的私钥：{}", Hex.encodeHexString(privateKey));
	}

	/**
	 * 测试：RSA算法公钥解密、私钥解密或者私钥加密、公钥解密
	 * 
	 * @throws Exception
	 */
	@Test
	public void testRSA() throws Exception {
		System.out.println("---------私钥加密，公钥解密---------");
		String inputStr1 = "RSA 非对称加密算法";
		logger.info("未经过任何处理的明文：{}", inputStr1);
		byte[] encryptData1 = RSACoder.encryptByPrivateKey(inputStr1.getBytes(), privateKey);
		logger.info("经过RSA加密算法私钥加密后生成的十六进制密文：{}", Hex.encodeHexString(encryptData1));
		byte[] decryptData1 = RSACoder.decryptByPublicKey(encryptData1,publicKey);
		logger.info("经过RSA加密算法公钥解密后生成的文本字符串形式的密文：{}",new String(decryptData1));

		System.out.println("---------公钥加密，私钥解密---------");
		String inputStr2 = "RSA 非对称加密算法";
		logger.info("未经过任何处理的明文：{}", inputStr2);
		byte[] encryptData2 = RSACoder.encryptByPublicKey(inputStr2.getBytes(),publicKey);
		logger.info("经过RSA加密算法公钥加密后生成的十六进制密文：{}", Hex.encodeHexString(encryptData2));
		byte[] decryptData2 = RSACoder.decryptByPrivateKey(encryptData2,privateKey);
		logger.info("经过RSA加密算法私钥解密后生成的文本字符串形式的密文：{}", new String(decryptData2));
	}
}
