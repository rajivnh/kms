package com.hcl.web;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.util.BinaryUtils;

@RestController
public class KmsSymmetricArn {	
	@Value("${kms.keyArn.symmetric}")
	private String keySymmetricArn;
	
	@GetMapping("/kms/symmetric/encrypt")
	public String encrypt() throws UnsupportedEncodingException {
		ByteBuffer plaintext = ByteBuffer.wrap(new String("Hello World").getBytes());
		
		EncryptRequest encryptRequest = new EncryptRequest().withKeyId(keySymmetricArn).withPlaintext(plaintext);
		
		AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
		
		ByteBuffer ciphertext = kmsClient.encrypt(encryptRequest).getCiphertextBlob();
		
		return new String(BinaryUtils.toBase64(ciphertext.array()).getBytes(), "utf-8");
	}
	
	@GetMapping("/kms/symmetric/decrypt")
	public String decrypt() throws UnsupportedEncodingException {
		ByteBuffer cypherTextBlob = ByteBuffer.wrap(Base64.getDecoder().decode("AQICAHjQnsCJ/vxdCo5UoCEx2/x5Ndj6h0681k3lj25T73BvoQFRa/CcJxmNCxhri+onOqnAAAAAaTBnBgkqhkiG9w0BBwagWjBYAgEAMFMGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMZoNqhtgOcAh1xaTaAgEQgCZwRK2MLligbjSBgwh8jQ6L/S0rhtKiKCCt1DfAoB7hRJ1/+UpWng=="));
		
		DecryptRequest decryptRequest = new DecryptRequest().withCiphertextBlob(cypherTextBlob);
		
		AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
		
		ByteBuffer ciphertext = kmsClient.decrypt(decryptRequest).getPlaintext();
		
		return StandardCharsets.UTF_8.decode(ciphertext).toString();
	}
}
