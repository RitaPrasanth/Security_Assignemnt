import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;



public class test_1
{
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        
        //adding security provider BouncyCastle
        Security.addProvider(new BouncyCastleProvider());

        
        //accepting message from user
        System.out.println("Enter the message to be hashed");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String message =br.readLine();
        
        
        
        //Using SHA to get digest of message 
        
        //creating instance of messageDigest using BouncycCastle provider
		MessageDigest digest=MessageDigest.getInstance("SHA-1","BC" );
		
		//using digest instance to past the message through hash algorithm
		byte[] hash  = digest.digest(message.getBytes(StandardCharsets.UTF_8)); 
		
		//convert the digest to string
		String shahex= new String(Hex.encode(hash));
		
		System.out.println("MESSAGE DIGEST: "+shahex+"\n");
		
		
		
		
		//USING RSA AS DIGITAL SIGNATURE
		
		//generate the keys for RSA
        KeyPairGenerator  key_gen = KeyPairGenerator.getInstance("RSA", "BC");
        KeyPair key_pair = key_gen.generateKeyPair();
        
        PrivateKey private_key = key_pair.getPrivate();
        PublicKey public_key = key_pair.getPublic();	
        
        //System.out.println(private_key);
        //System.out.println(public_key);
        
   
        
        
        
        
        //GENERATING DIGITAL SIGNATURE
        
        //Encrypt the digest to get digital signature
        Cipher cipher=Cipher.getInstance("RSA","BC");
        cipher.init(Cipher.ENCRYPT_MODE, private_key);
        byte[] enc_text=cipher.doFinal(hash);
        
        
        System.out.println("DIGITAL SIGNATURE: "+enc_text+"");
        

        
        
        
        
        //VERIFYING THE DIGITAL SIGNATURE
        
        //Decrypt the signature using public key
        cipher=Cipher.getInstance("RSA","BC");
        cipher.init(Cipher.DECRYPT_MODE,public_key);
        byte[] dec_text=cipher.doFinal(enc_text);
        String output=new String (Hex.encode(dec_text));
        
        System.out.println("\nDECRPTED VALUE: "+output);      

        
        
        //checking the decrypted value with digest from message
        
        if(shahex.equals(output))
        	System.out.println("\nSIGNATURE VERIFIED");      
        
		

		
    }
    
    
}
