package cn.ubingo.security.interop;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.xml.parsers.*;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.lang.*;

/*
 Jeffrey Walton
 http://www.codeproject.com/Articles/25487/Cryptographic-Interoperability-Keys
 */
public class XmlKeyBuilder {
	public static String publicKeyToXML(PublicKey key) {
		if (!RSAPublicKey.class.isInstance(key)) {
			return null;
		}
		RSAPublicKey pubKey = (RSAPublicKey) key;
		StringBuilder sb = new StringBuilder();

		sb.append("<RSAKeyValue>");
		sb.append("<Modulus>")
				.append(new BASE64Encoder().encode(TrimLeadingZero(pubKey.getModulus()
						.toByteArray()))).append("</Modulus>");
		sb.append("<Exponent>")
				.append(new BASE64Encoder().encode(TrimLeadingZero(pubKey.getPublicExponent()
						.toByteArray()))).append("</Exponent>");
		sb.append("</RSAKeyValue>");
		return sb.toString();
	}

	public static String privateKeyToXML(PrivateKey key) {
		if (!RSAPrivateCrtKey.class.isInstance(key)) {
			return null;
		}
		RSAPrivateCrtKey priKey = (RSAPrivateCrtKey) key;
		StringBuilder sb = new StringBuilder();

		sb.append("<RSAKeyValue>");
		sb.append("<Modulus>")
				.append(new BASE64Encoder().encode(TrimLeadingZero(priKey.getModulus()
						.toByteArray()))).append("</Modulus>");
		sb.append("<Exponent>")
				.append(new BASE64Encoder().encode(TrimLeadingZero(priKey.getPublicExponent()
						.toByteArray()))).append("</Exponent>");
		sb.append("<P>")
				.append(new BASE64Encoder().encode(TrimLeadingZero(priKey.getPrimeP()
						.toByteArray()))).append("</P>");
		sb.append("<Q>")
				.append(new BASE64Encoder().encode(TrimLeadingZero(priKey.getPrimeQ()
						.toByteArray()))).append("</Q>");
		sb.append("<DP>")
				.append(new BASE64Encoder().encode(TrimLeadingZero(priKey.getPrimeExponentP()
						.toByteArray()))).append("</DP>");
		sb.append("<DQ>")
				.append(new BASE64Encoder().encode(TrimLeadingZero(priKey.getPrimeExponentQ()
						.toByteArray()))).append("</DQ>");
		sb.append("<InverseQ>")
				.append(new BASE64Encoder().encode(TrimLeadingZero(priKey.getCrtCoefficient()
						.toByteArray()))).append("</InverseQ>");
		sb.append("<D>")
				.append(new BASE64Encoder().encode(TrimLeadingZero(priKey.getPrivateExponent()
						.toByteArray()))).append("</D>");
		sb.append("</RSAKeyValue>");
		return sb.toString();
	}

	public static PublicKey xmlToPublicKey(String key)
			throws ParserConfigurationException, SAXException, IOException {
		key = key.replaceAll("\r", "").replaceAll("\n", "");
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc = builder.parse(new InputSource(new ByteArrayInputStream(
				key.getBytes("utf-8"))));
		String n = doc.getDocumentElement().getElementsByTagName("Modulus")
				.item(0).getTextContent();
		String e = doc.getDocumentElement().getElementsByTagName("Exponent")
				.item(0).getTextContent();
		BigInteger modulus = new BigInteger(1,
				new BASE64Decoder().decodeBuffer(n));
		BigInteger publicExponent = new BigInteger(1,
				new BASE64Decoder().decodeBuffer(e));

		RSAPublicKeySpec rsaPubKey = new RSAPublicKeySpec(modulus,
				publicExponent);

		KeyFactory keyf;
		try {
			keyf = KeyFactory.getInstance("RSA");
			return keyf.generatePublic(rsaPubKey);
		} catch (Exception ex) {
			return null;
		}
	}

	public static PrivateKey xmlToPrivateKey(String key) throws IOException,
			SAXException, ParserConfigurationException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc = builder.parse(new InputSource(new ByteArrayInputStream(
				key.getBytes("utf-8"))));
		String n = doc.getDocumentElement().getElementsByTagName("Modulus")
				.item(0).getTextContent();
		String e = doc.getDocumentElement().getElementsByTagName("Exponent")
				.item(0).getTextContent();
		String d = doc.getDocumentElement().getElementsByTagName("D").item(0)
				.getTextContent();
		String p = doc.getDocumentElement().getElementsByTagName("P").item(0)
				.getTextContent();
		String q = doc.getDocumentElement().getElementsByTagName("Q").item(0)
				.getTextContent();
		String dp = doc.getDocumentElement().getElementsByTagName("DP").item(0)
				.getTextContent();
		String dq = doc.getDocumentElement().getElementsByTagName("DQ").item(0)
				.getTextContent();
		String inverseQ = doc.getDocumentElement()
				.getElementsByTagName("InverseQ").item(0).getTextContent();

		key = key.replaceAll("\r", "").replaceAll("\n", "");
		BigInteger modulus = new BigInteger(1,
				new BASE64Decoder().decodeBuffer(n));
		BigInteger publicExponent = new BigInteger(1,
				new BASE64Decoder().decodeBuffer(e));
		BigInteger privateExponent = new BigInteger(1,
				new BASE64Decoder().decodeBuffer(d));
		BigInteger primeP = new BigInteger(1,
				new BASE64Decoder().decodeBuffer(p));
		BigInteger primeQ = new BigInteger(1,
				new BASE64Decoder().decodeBuffer(q));
		BigInteger primeExponentP = new BigInteger(1,
				new BASE64Decoder().decodeBuffer(dp));
		BigInteger primeExponentQ = new BigInteger(1,
				new BASE64Decoder().decodeBuffer(dq));
		BigInteger crtCoefficient = new BigInteger(1,
				new BASE64Decoder().decodeBuffer(inverseQ));

		RSAPrivateCrtKeySpec rsaPriKey = new RSAPrivateCrtKeySpec(modulus,
				publicExponent, privateExponent, primeP, primeQ,
				primeExponentP, primeExponentQ, crtCoefficient);

		KeyFactory keyf;
		try {
			keyf = KeyFactory.getInstance("RSA");
			return keyf.generatePrivate(rsaPriKey);
		} catch (Exception ex) {
			return null;
		}
	}

	static byte[] TrimLeadingZero(byte[] values) {
		if ((0x00 == values[0]) && (values.length > 1)) {
			byte[] r = null;
			r = new byte[values.length - 1];
			System.arraycopy(values,1,r,0,r.length);
			return r;
		} 

		return values;
	}
}
