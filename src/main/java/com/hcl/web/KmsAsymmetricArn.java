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
import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.amazonaws.util.BinaryUtils;

@RestController
public class KmsAsymmetricArn {	
	@Value("${kms.keyArn.asymmetric}")
	private String keyAsymmetricArn;
	
	@GetMapping("/kms/asymmetric/encrypt")
	public String encrypt() throws UnsupportedEncodingException {
		ByteBuffer plaintext = ByteBuffer.wrap(new String("Hello World").getBytes());
		
		EncryptRequest encryptRequest = new EncryptRequest().withEncryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256).withKeyId(keyAsymmetricArn).withPlaintext(plaintext);
		
		AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
		
		ByteBuffer ciphertext = kmsClient.encrypt(encryptRequest).getCiphertextBlob();
		
		return new String(BinaryUtils.toBase64(ciphertext.array()).getBytes(), "utf-8");
	}

	@GetMapping("/kms/asymmetric/decrypt")
	public String decrypt() throws UnsupportedEncodingException {
		ByteBuffer cypherTextBlob = ByteBuffer.wrap(Base64.getDecoder().decode("wS7GUuxbK4M7proEwyxUnh9aoh2e2vNuYmKmEmE9/DT8g4P07Agoshgv0mVPjznBrwiU7eJjDeLYeyKrtZ50hiSMCX1QlxEizn4sLvWpspJnl4qnzggCvmXxmvOLPbxlHqi+DAOIEFI6/M/7caRSnc1XJ9hB0zdIal15vxBER7C3I1Apm19Wc/O71q6qCucaI1pS0f0iwHSjklUtKCK0rG3O6+VeF6Tjls5bF7Y7hkx3XjqSgaKmuY5i2DLY93apRhr5zIovfwUXwcWOQqAMOQ+RI93ZP2bCXVlgOpNla9VLUSjLLaabIzGzHWPD3mQl4TyucbArQk8sfn0rgn/Eog=="));
		
		DecryptRequest decryptRequest = new DecryptRequest().withEncryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256).withKeyId(keyAsymmetricArn).withCiphertextBlob(cypherTextBlob);
		
		AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
		
		ByteBuffer ciphertext = kmsClient.decrypt(decryptRequest).getPlaintext();
		
		return StandardCharsets.UTF_8.decode(ciphertext).toString();
	}
}
