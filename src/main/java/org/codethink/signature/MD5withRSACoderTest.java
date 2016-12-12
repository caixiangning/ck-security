package org.codethink.signature;

import java.util.Map;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * RSA数字签名算法测试类
 * 
 * @author CaiXiangNing
 * @date 2016年12月11日
 * @email caixiangning@gmail.com
 */
public class MD5withRSACoderTest {
	
	private static final Logger logger = LoggerFactory.getLogger(MD5withRSACoderTest.class);
	// 公钥
	private byte[] publicKeyByte;
	// 私钥
	private byte[] privateKeyByte;

	/**
	 * 准备：生成公钥和私钥
	 * 
	 * @throws Exception
	 */
	@Before
	public void generateKey() throws Exception {
		Map<String, Object> keyMap = MD5withRSACoder.generateKey();
		publicKeyByte = MD5withRSACoder.getPublicKey(keyMap);
		privateKeyByte = MD5withRSACoder.getPrivateKey(keyMap);

		logger.info("使用密钥生成器生成的十六进制形式的公钥：{}", Hex.encodeHexString(publicKeyByte));
		logger.info("使用密钥生成器生成的十六进制形式的私钥：{}", Hex.encodeHexString(privateKeyByte));
	}

	/**
	 * 数字签名算法签名和校验
	 * 
	 * @throws Exception
	 */
	@Test
	public void testMD5withRSA() throws Exception {
		String inputStr = "RSA 数字签名算法";
		// 获取签名
		byte[] signByte = MD5withRSACoder.sign(inputStr.getBytes(), privateKeyByte);
		logger.info("经过RSA数字签名算法签名后生成的十六进制密文：{}", Hex.encodeHexString(signByte));

		// 验证签名
		boolean verifyStatus = MD5withRSACoder.verify(inputStr.getBytes(), publicKeyByte, signByte);
		logger.info("经过RSA数字签名算法验证后的结果：{}", verifyStatus);

		Assert.assertTrue(verifyStatus);
	}
}
