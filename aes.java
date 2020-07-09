//aes加密+base64加密
	public static String encryptPKCS5(String source, String key) throws Exception {
		byte[] sourceBytes = source.getBytes(StandardCharsets.UTF_8);
		byte[] keyBytes = key.getBytes();
		//Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(1, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(key.substring(0, 16).getBytes()));
		byte[] decrypted = cipher.doFinal(sourceBytes);
		return Base64.encodeBase64String(decrypted);
	}


	//base64解密+aes解密
	public static String dncryptPKCS5(String source, String key) throws Exception {
		byte[] sourceBytes = Base64.decodeBase64(source);
		//byte[] sourceBytes = source.getBytes(StandardCharsets.UTF_8);
		byte[] keyBytes = key.getBytes();
		//Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(2, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(key.substring(0, 16).getBytes()));

		byte[] decrypted = cipher.doFinal(sourceBytes);

		return new String(decrypted);
	}
————————————————
版权声明：本文为CSDN博主「Goytao」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/Goytao/java/article/details/106302127