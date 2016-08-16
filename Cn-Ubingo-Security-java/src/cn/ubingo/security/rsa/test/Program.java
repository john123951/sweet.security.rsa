package cn.ubingo.security.rsa.test;

import cn.ubingo.security.rsa.core.*;
import cn.ubingo.security.rsa.data.*;
import cn.ubingo.security.rsa.key.*;
/*
陈服建(fochen,j@ubingo.cn)
2015-01-23
*/
public class Program {
	public static void main(String[] args) throws Exception
    {
		//生成密钥对
        KeyPair keyPair = KeyGenerator.generateKeyPair();
        
        //转换成不同的格式
        KeyPair asnKeyPair = keyPair.toASNKeyPair();
        KeyPair xmlKeyPair = asnKeyPair.toXMLKeyPair();
        KeyPair pemKeyPair = xmlKeyPair.toPEMKeyPair();
        
        //获取公私钥，以asn格式的为例
        String publicKey = asnKeyPair.getPublicKey();
        String privateKey = asnKeyPair.getPrivateKey();
        
        //ASN
        KeyWorker privateWorker = new KeyWorker(privateKey, KeyFormat.ASN);
        KeyWorker publicWorker = new KeyWorker(publicKey, KeyFormat.ASN);
                    
        System.out.print(privateWorker.decrypt(publicWorker.encrypt("你好！世界")));
        System.out.print(publicWorker.decrypt(privateWorker.encrypt("你好！中国")));

        //XML
        privateWorker = new KeyWorker(xmlKeyPair.getPrivateKey(), KeyFormat.XML);
        publicWorker = new KeyWorker(xmlKeyPair.getPublicKey(), KeyFormat.XML);

        System.out.print(privateWorker.decrypt(publicWorker.encrypt("你好！世界")));
        System.out.print(publicWorker.decrypt(privateWorker.encrypt("你好！中国")));

        //PEM
        privateWorker = new KeyWorker(pemKeyPair.getPrivateKey(), KeyFormat.PEM);
        publicWorker = new KeyWorker(pemKeyPair.getPublicKey(), KeyFormat.PEM);

        System.out.print(privateWorker.decrypt(publicWorker.encrypt("你好！世界")));
        System.out.print(publicWorker.decrypt(privateWorker.encrypt("你好！中国")));
        
    }
}
