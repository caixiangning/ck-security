package org.codethink.asymmetricencryption;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

/**
 * 
 * 非对称算法RSA算法实现类
 * 
 * RSA算法的密钥长度是512至65536位(密钥长度为64的倍数，范围在512～65536位之间)，
 * JDK实现的RSA算法的密钥长度默认值是1024。Bouncy Castle实现的RSA算法的密钥长度默认值是2048。
 * 非对称加密算法RSA的通信模型： 
 * a、首先由消息发送方构建密钥对(公钥和私钥)
 * b、接着由密钥构建者发送方向消息接收方公布其公钥。 
 * c、由消息发送方通过私钥加密数据，并将加密数据发送给接收者。
 * d、由消息接收者接收加密数据并使用公钥解密数据。 
 * 附：这是典型的私钥加密、公钥解密，RSA算法还支持公钥加密、私钥解密这种方式。
 * 但是注意一点，私钥是不能公开的，公钥是必须公开的。
 * 附：抽象类不能实例化，但是仍然可以通过类调用静态方法还能防止实例化(不错的思路)
 * 
 * @author CaiXiangNing
 * @date 2016年12月11日
 * @email caixiangning@gmail.com
 */
public abstract class RSACoder {
	
	// 非对称加密密钥算法RSA
	public static final String KEY_ALGORITHM = "RSA";

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
	 * 公钥加密
	 * 
	 * @param data 待加密的明文
	 * @param publicKeyBytes 字节数组形式的公钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, byte[] publicKeyBytes)
			throws Exception {
		// 根据字节数组形式的公钥转换为PublicKey类型的公钥
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
		// 使用公钥作为密钥对数据进行加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}

	/**
	 * 私钥解密
	 * 
	 * @param data 待解密的密文
	 * @param privateKeyBytes 字节数组形式的密钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data, byte[] privateKeyBytes)
			throws Exception {
		// 根据字节数组形式的私钥转换为PrivateKey类型的私钥
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		// 使用私钥作为密钥对数据进行解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}

	/**
	 * 私钥加密
	 * 
	 * @param data 待加密的明文
	 * @param privateKeyBytes 字节数组形式的私钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, byte[] privateKeyBytes) 
			throws Exception {
		// 根据字节数组形式的私钥转换为PrivateKey类型的私钥
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec( privateKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		// 使用私钥作为密钥对数据进行加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}

	/**
	 * 公钥解密
	 * 
	 * @param data 待解密的密文
	 * @param publicKeyBytes 字节数组形式的公钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, byte[] publicKeyBytes) 
			throws Exception {
		// 根据字节数组形式的公钥转换为PublicKey类型的公钥
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
		// 使用公钥作为密钥对数据进行解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(data);
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
