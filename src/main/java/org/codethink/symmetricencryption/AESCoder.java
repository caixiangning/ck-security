package org.codethink.symmetricencryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * 对称加密算法之AES算法实现类
 * 
 * @author CaiXiangNing
 * @date 2016年12月11日
 * @email caixiangning@gmail.com
 */
public abstract class AESCoder {

	// 密钥算法
	public static final String KEY_ALGORITHM = "AES";
	// 工作模式和填充方式
	public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

	/**
	 * 生成密钥 每次使用密钥生成器生成的密钥是不同的
	 * 
	 * @return 字节数组形式的密钥
	 * @throws Exception
	 */
	public static byte[] generateSecretKey() throws Exception {
		// 实例化密钥生成器
		KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
		// AES要求密钥长度为128位、192位或256位，默认128位
		keyGenerator.init(128);
		// 生成密钥(Key类型)
		SecretKey secretKey = keyGenerator.generateKey();
		// 生成字节数组形式的密钥
		// 附：使用字节数组便于存储在文件中，或者以数据流的形式在网络上传输
		return secretKey.getEncoded();
	}

	/**
	 * 字节数组形式的密钥转换为Key类型的密钥
	 * 附：字节数组形式的密钥便于保存或者在网络上传输，但是如果使用还得转换为Key类型的密钥对象
	 * 
	 * @param key 字节数组形式的密钥
	 * @return
	 * @throws Exception
	 */
	public static SecretKey byteArrayToKey(byte[] keyByte) throws Exception {
		// 生成Key类型的密钥
		SecretKey secretKey = new SecretKeySpec(keyByte, KEY_ALGORITHM);
		return secretKey;
	}

	/**
	 * 加密操作
	 * 
	 * @param data 待加密的字节数组形式的明文
	 * @param keyByte 字节数组形式的密钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] data, byte[] keyByte) throws Exception {
		// 字节数组形式的密钥转换为Key类型的密钥
		SecretKey secretKey = byteArrayToKey(keyByte);
		// 执行工作模式和填充方式
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		// 初始化Cipher，设置为加密模式
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		// 执行加密操作
		return cipher.doFinal(data);
	}

	/**
	 * 解密操作
	 * 
	 * @param data 待解密的字节数组形式的密文
	 * @param keyByte 字节数组形式的密钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] data, byte[] keyByte) throws Exception {
		// 字节数组形式的密钥转换为Key类型的密钥
		SecretKey secretKey = byteArrayToKey(keyByte);
		// 执行工作模式和填充方式
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		// 初始化Cipher，设置为解密模式
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		// 执行解密操作
		return cipher.doFinal(data);
	}
}
