package org.codethink.certificate;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

/**
 * 
 * 基于密钥库和数字证书的加密/解密和签名/验证操作的实现类
 * 
 * @author CaiXiangNing
 * @date 2016年12月13日
 * @email caixiangning@gmail.com
 */
public abstract class CertificateCoder {
	
	// 类型证书X509
	public static final String CERT_TYPE = "X.509";
	
	/**
	 * 获取KeyStore
	 * @param keyStorePath 密钥库路径
	 * @param password 密码
	 * @return
	 * @throws Exception
	 */
	private static KeyStore getKeyStore(String keyStorePath, String password) throws Exception{
		// 实例化密钥库
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		// 获得密钥库文件流
		FileInputStream fileInputStream = new FileInputStream(keyStorePath);
		// 加载密钥库
		keyStore.load(fileInputStream, password.toCharArray());
		// 关闭密钥库文件流
		fileInputStream.close();
		return keyStore;
	}
	
	/**
	 * 由KeyStore获得私钥
	 * @param keyStorePath 密钥库路径
	 * @param alias 别名
	 * @param password 密码
	 * @return
	 * @throws Exception
	 */
	private static PrivateKey getPrivateKeyByKeyStore(String keyStorePath, String alias, String password) throws Exception{
		// 获得密钥库
		KeyStore keyStore = getKeyStore(keyStorePath, password);
		// 获得私钥
		return (PrivateKey)keyStore.getKey(alias, password.toCharArray());
	}
	
	/**
	 * 获取证书Certificate
	 * @param certificatePath 证书路径
	 * @return
	 * @throws Exception
	 */
	private static Certificate getCertificate(String certificatePath) throws Exception{
		// 实例化证书工厂
		CertificateFactory certificateFactory = CertificateFactory.getInstance(CERT_TYPE);
		// 取得证书文件流
		FileInputStream fileInputStream = new FileInputStream(certificatePath);
		// 生成证书
		Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
		// 关闭证书文件流
		fileInputStream.close();
		return certificate;
	}
	
	/**
	 * 获取证书Certificate
	 * @param keyStorePath 密钥库路径
	 * @param alias 别名
	 * @param password 密码
	 * @return
	 * @throws Exception
	 */
	private static Certificate getCertificate(String keyStorePath, String alias, String password) throws Exception{
		// 获得密钥库
		KeyStore keyStore = getKeyStore(keyStorePath, password);
		// 获得证书
		return keyStore.getCertificate(alias);
	}
	
	/**
	 * 由Certificate获得公钥
	 * @param certificatePath 证书路径
	 * @return
	 * @throws Exception
	 */
	private static PublicKey getPublicKeyByCertificate(String certificatePath) throws Exception{
		// 获得证书
		Certificate certificate = getCertificate(certificatePath);
		// 获得公钥
		return certificate.getPublicKey();
	}
	
	/**
	 * 私钥加密
	 * @param data 待加密数据
	 * @param keyStorePath 密钥库路径
	 * @param alias 别名
	 * @param password 密码
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, String keyStorePath, String alias, String password) throws Exception{
		// 获取私钥
		PrivateKey privateKey = getPrivateKeyByKeyStore(keyStorePath, alias, password);
		// 对数据进行加密
		Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}
	
	/**
	 * 私钥解密
	 * @param data 待解密数据
	 * @param keyStorePath 密钥库路径
	 * @param alias 别名
	 * @param password 密码
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data, String keyStorePath, String alias, String password) throws Exception{
		// 获取私钥
		PrivateKey privateKey = getPrivateKeyByKeyStore(keyStorePath, alias, password);
		// 对数据进行解密
		Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}
	
	/**
	 * 公钥加密
	 * @param data 待加密数据
	 * @param certificatePath 证书路径
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, String certificatePath) throws Exception{
		// 获取公钥
		PublicKey publicKey = getPublicKeyByCertificate(certificatePath);
		// 对数据进行加密
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}
	
	/**
	 * 公钥解密
	 * @param data 待加密数据
	 * @param certificatePath 证书路径
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, String certificatePath) throws Exception{
		// 获取公钥
		PublicKey publicKey = getPublicKeyByCertificate(certificatePath);
		// 对数据进行加密
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}
	
	/**
	 * 签名
	 * @param data 待签名数据
	 * @param keyStorePath 密钥库路径
	 * @param alias 别名
	 * @param password 密码
	 * @return
	 * @throws Exception
	 */
	public static byte[] sign(byte[] data, String keyStorePath, String alias, String password) throws Exception{
		// 获得证书
		X509Certificate x509Certificate = (X509Certificate)getCertificate(keyStorePath, alias, password);
		// 构建签名,由证书指定签名算法:SHA1withRSA
		Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
		// 获取私钥
		PrivateKey privateKey = getPrivateKeyByKeyStore(keyStorePath, alias, password);
		// 初始化签名，由私钥构建
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}
	
	/**
	 * 验证签名
	 * @param data 未签名的明文数据
	 * @param sign 签名数据
	 * @param certificatePath 证书路径
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(byte[] data, byte[] sign, String certificatePath) throws Exception{
		// 获得证书
		X509Certificate x509Certificate = (X509Certificate)getCertificate(certificatePath);
		// 由证书构建签名
		Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
		// 由证书初始化签名，实际上是使用了证书中的公钥
		signature.initVerify(x509Certificate);
		signature.update(data);
		return signature.verify(sign);
	}
}
