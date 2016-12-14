package org.codethink.certificate;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * 基于密钥库和数字证书的加密/解密和签名/验证操作的测试类
 * 
 * @author CaiXiangNing
 * @date 2016年12月14日
 * @email caixiangning@gmail.com
 */
public class CertificateCoderTest {
	private String password = "caixiangning";
	private String alias = "www.codethink.com";
	private String certificatePath = "d:/codethink.cer";
	private String keyStorePath = "d:/codethink.keystore";
	
	private static final Logger logger = LoggerFactory.getLogger(CertificateCoderTest.class);
	
	/**
	 * 公钥加密--私钥解密
	 * @throws Exception
	 */
	@Test
	public void test1() throws Exception{
		System.out.println("公钥加密--私钥解密：");
		String inputStr = "数字证书";
		byte[] data = inputStr.getBytes();
		// 公钥加密
		byte[] encodedData = CertificateCoder.encryptByPublicKey(data, certificatePath);
		// 私钥解密
		byte[] decodedData = CertificateCoder.decryptByPrivateKey(encodedData, keyStorePath, alias, password);
		String outputStr = new String(decodedData);
		logger.info("加密前：\n{}", inputStr);
		logger.info("解密后：\n{}", outputStr);
		// 验证数据一致
		Assert.assertEquals(data, decodedData);
	}
	
	/**
	 * 私钥加密--公钥解密
	 * @throws Exception
	 */
	@Test
	public void test2() throws Exception{
		System.out.println("私钥加密--公钥解密：");
		String inputStr = "数字签名";
		byte[] data = inputStr.getBytes();
		// 私钥加密
		byte[] encodedData = CertificateCoder.encryptByPrivateKey(data, keyStorePath, alias, password);
		// 公钥解密
		byte[] decodedData = CertificateCoder.decryptByPublicKey(encodedData, certificatePath);
		String outputStr = new String(decodedData);
		logger.info("加密前：\n{}", inputStr);
		logger.info("解密后：\n{}", outputStr);
		// 验证数据一致
		Assert.assertEquals(data, decodedData);
	}
	
	/**
	 * 签名验证(私钥签名--公钥验证)
	 * @throws Exception
	 */
	@Test
	public void testSign() throws Exception{
		System.out.println("私钥签名--公钥验证：");
		String inputStr = "签名";
		byte[] data = inputStr.getBytes();
		// 生成签名
		byte[] sign = CertificateCoder.sign(data, keyStorePath, alias, password);
		logger.info("生成的签名：\n{}", Hex.encodeHexString(sign));
		// 验证签名
		boolean status = CertificateCoder.verify(data, sign, certificatePath);
		logger.info("签名验证结果状态：\n{}", status);
		// 验证数据一致
		Assert.assertTrue(status);
	}
}
