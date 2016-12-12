package org.codethink.signature;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * 
 * RSA数字签名算法实现类
 * 
 * @author CaiXiangNing
 * @date 2016年12月11日
 * @email caixiangning@gmail.com
 */
public abstract class MD5withRSACoder {
	
	// 数字签名 密钥算法
	public static final String KEY_ALGORITHM = "RSA";

	// 数字签名 签名/验证算法
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

	// RSA算法的密钥长度是512至65536位(密钥长度为64的倍数，范围在512～65536位之间)
	// JDK实现的RSA算法的密钥长度默认值是1024。Bouncy Castle实现的RSA算法的密钥长度默认值是2048。
	private static final int KEY_SIZE = 512;

	// 公钥
	private static final String PUBLIC_KEY = "RSAPublicKey";
	// 私钥
	private static final String PRIVATE_KEY = "RSAPrivateKey";

	/**
	 * 发送方构建密钥(公钥、私钥)
	 * 
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> generateKey() throws Exception {
		// 实例化密钥对生成器
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		// 指定密钥对生成器生成密钥的长度
		keyPairGenerator.initialize(KEY_SIZE);
		// 生成密钥对
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		// 公钥
		PublicKey publicKey = keyPair.getPublic();
		// 私钥
		PrivateKey privateKey = keyPair.getPrivate();

		// 将密钥对存储在Map中并返回
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}

	/**
	 * 签名操作
	 * 
	 * @param data 待签名的数据
	 * @param privateKeyBytes 私钥
	 * @return 数字签名
	 * @throws Exception
	 */
	public static byte[] sign(byte[] data, byte[] privateKeyBytes)
			throws Exception {
		// 根据字节数组形式的私钥转换为PrivateKey类型的私钥
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

		// 签名操作
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}

	/**
	 * 验证操作
	 * 
	 * @param data 待校验的数据
	 * @param publicKeyByte 字节数组形式的公钥
	 * @param signByte 数字签名
	 * @return 校验成功返回true，校验失败返回false
	 * @throws Exception
	 */
	public static boolean verify(byte[] data, byte[] publicKeyByte,
			byte[] signByte) throws Exception {
		// 根据字节数组形式的公钥转换为PublicKey类型的公钥
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyByte);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

		// 验证操作
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(signByte);
	}

	/**
	 * 在Map中获取公钥
	 * 
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPublicKey(Map<String, Object> keyMap) {
		PublicKey publicKey = (PublicKey) keyMap.get(PUBLIC_KEY);
		return publicKey.getEncoded();
	}

	/**
	 * 在Map中获取私钥
	 * 
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPrivateKey(Map<String, Object> keyMap) {
		PrivateKey privateKey = (PrivateKey) keyMap.get(PRIVATE_KEY);
		return privateKey.getEncoded();
	}
}
