import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;





public class Client {
    public static final String IP_ADDRESS = "127.0.0.1";
    public static final int PORT = 5003;
   // public static HashMap<String ,BigInteger> info=new HashMap<>();
    public static HashMap<String, SecretKey> sessionKeys = new HashMap<>();
    private static BigInteger privateKey;
    private static BigInteger N;
    public static String clientId;

    public static BigInteger getN(){
        return N;
    }
    public static BigInteger getPrivateKey()
    {
        return privateKey;
    }
    
    


    public static void main(String[] args) throws IOException {
        Socket socket = new Socket(IP_ADDRESS, PORT);
        
        Rsa rsa=new Rsa();
        BigInteger publicKey=rsa.getPublicKey();
        privateKey=rsa.getPrivateKey();
        N=rsa.getN();

        ServerConnection serverConnection = new ServerConnection(socket);
        BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
        PrintWriter output = new PrintWriter(socket.getOutputStream(), true);

        output.println("PUBLIC_KEY:" + publicKey);
        output.println("N:" + N);
        

        
      

        // client server dan gelen mesajları dinliyor...
        new Thread(serverConnection).start();
       
       

        while (true) {
            System.out.println("[CLIENT] --> (Mesajinizi yazin veya '[kime:kullaniciAdi] mesaj' formatinda mesaj gönderin).Sistemden cikmak istiyorsaniz Bitti yazabilirsiniz:");
            String message = keyboard.readLine();
             
            //Belirtilen String ifade ile başlıyorsa
            if (message.startsWith("[kime:")) {
            int endIndex = message.indexOf("]");
            if (endIndex != -1) {
            String targetId = message.substring(6, endIndex);
            String msg = message.substring(endIndex + 1).trim();
            if (clientId.equals(targetId)) {
                System.out.println("Kendi kendinize mesaj gönderemezsiniz.");
                continue;
            }
            output.println("[kime:" + targetId + "]");
        // Kullanıcıya imzalama seçeneği sunuyoruz.
        String response;
        while(true){
             System.out.println("Mesaji imzalamak ister misiniz? (E/H):");
              response = keyboard.readLine();
             if(response.equalsIgnoreCase("E")||response.equalsIgnoreCase("H"))
                break;
                System.out.println("Lutfen Mesaji imzalamak iste rmisiniz? sorusuna (E/H) seklinde cevap verin.");
        }
       
       
        try {
            if (response.equalsIgnoreCase("E")) {
                String signature = signMessage(msg);
                message = "[kime:" + targetId + "][SIGNED]" + encryptMessage(msg, targetId) + "[SIG]" + signature;
            } else {
                message = "[kime:" + targetId + "]" + encryptMessage(msg, targetId);
            }
        } catch (Exception e) {
            e.getStackTrace();
        }
       
    }
}
        output.println(message);
        if (message.equalsIgnoreCase("Bitti.")) {
            break;
        }
    }
    socket.close();
    System.exit(0);
}
 private static String encryptMessage(String message, String targetId) throws Exception {
        SecretKey sessionKey = sessionKeys.get(targetId);
        if (sessionKey == null){
            System.out.println("[UYARI]: Hedef istemci için oturum anahtari bulunamadi.");
            return message;
        } 
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        String siferlenmis_mesaj=Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("Sifrelenmis Mesaj:"+siferlenmis_mesaj);
        return siferlenmis_mesaj;

    }

    public static String decryptMessage(String message, String senderId) throws Exception {
        SecretKey sessionKey = sessionKeys.get(senderId);
        if (sessionKey == null)
        {
             System.out.println("[UYARI]: Hedef istemci için oturum anahtari bulunamadi.");
            return message;
        }
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message));
        System.out.println("desifre edilmis mesaj:"+decryptedBytes);
        return new String(decryptedBytes);

    }
    // Mesajın hash'ini al ve private key ile imzalar
    public static String signMessage(String message) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = md.digest(message.getBytes()); // Hash değerini al

        //  Hash değerini BigInteger formatına çevir
        BigInteger messageInt = new BigInteger(1, messageHash); // Pozitif BigInteger

        //  RSA imzası oluştur
        BigInteger signature = messageInt.modPow(privateKey, N);

        //  İmzayı Base64 formatında döndür
        return Base64.getEncoder().encodeToString(signature.toByteArray());
    }

    
    // İmzayı doğrular
    public static boolean verifySignature(String message, String signature, BigInteger publicKey, BigInteger N) throws Exception {
         // 1. İmza Base64'ten decode edilip BigInteger'e dönüştürülür
         byte[] signatureBytes = Base64.getDecoder().decode(signature);
         BigInteger signatureInt = new BigInteger(signatureBytes);
 
         // 2. İmza açık anahtarla çözülür
         BigInteger decryptedSignature = signatureInt.modPow(publicKey, N);
 
         // 3. Çözülen imzanın hash değeri alınır
         byte[] decryptedBytes = decryptedSignature.toByteArray();
 
         // 4. Mesajın hash değerini hesapla (SHA-256 kullanarak)
         MessageDigest md = MessageDigest.getInstance("SHA-256");
         byte[] messageHash = md.digest(message.getBytes());
 
         // 5. Çözülen hash ile mesajın hash değeri karşılaştırılır
         return new BigInteger(1, messageHash).equals(new BigInteger(1, decryptedBytes));
    }
    
    /*public static void setClientId(String clientId) {
        info.put(clientId, privateKey);
    }*/
    public static synchronized void sessionKeys(String targetId, SecretKey sessionKey) {
        
       sessionKeys.put(targetId,sessionKey);
    }
    
  
}

