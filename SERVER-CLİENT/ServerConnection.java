import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
//İstemcinin sunucudan gelen mesajları dinlemesini ve ekranda görüntülemesini sağlar.

public class ServerConnection implements Runnable {
    private Socket socket;
    private BufferedReader input;
    private BigInteger senderPublicKey;
    private BigInteger senderN;
    int counter=0;
    String serverResponse;
    public ServerConnection(Socket socket) throws IOException {
        this.socket = socket;
        input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    }

    @Override
    public void run() {
        try {
            
           
            while ((serverResponse = input.readLine()) != null) {
                int sonkarakter=serverResponse.indexOf("!");
                if(sonkarakter!=-1){
                Client.clientId=serverResponse.substring(13, sonkarakter);
                }
               
                if (serverResponse.startsWith("SESSION_KEY:")) {
                    String[] parts = serverResponse.split(":");
                    String encryptedKey = parts[1];
                     String targetId = parts[2];
                  
                    BigInteger decryptedKey = new BigInteger(encryptedKey)
                        .modPow(Client.getPrivateKey(), Client.getN());
                    byte[] keyBytes = decryptedKey.toByteArray();
                    
                    SecretKey sessionKey = new SecretKeySpec(keyBytes, 0, 16, "AES");
                     Client.sessionKeys(targetId,sessionKey);
                    System.out.println("Oturum anahtari alindi ve eklendi: " + targetId+":"+sessionKey);
                    continue;
                }
               
                else if (serverResponse.startsWith("(")) {
                    int endIndex = serverResponse.indexOf(")");
                    if (endIndex != -1) {
                        String senderId = serverResponse.substring(1, endIndex);
                        String msg = serverResponse.substring(endIndex + 2).trim();
                        
                        if (msg.contains("[PUBKEY]")) {
                            // Public key bilgisini al ve sakla
                            String[] parts = msg.split("\\[PUBKEY\\]");
                            msg = parts[0];
                            String[] keyParts = parts[1].split(":");
                            senderPublicKey = new BigInteger(keyParts[0]);
                            senderN = new BigInteger(keyParts[1]);
                        }
                        
                        try {
                            String decryptedMsg;
                            if (msg.contains("[SIGNED]")) {
                                String[] parts = msg.split("\\[SIG\\]");
                                String encryptedMsg = parts[0].replace("[SIGNED]", "");
                                String signature = parts[1];
                                decryptedMsg = Client.decryptMessage(encryptedMsg, senderId);
                                
                                // İmza doğrulama
                                if (Client.verifySignature(decryptedMsg, signature, senderPublicKey, senderN)) {
                                    serverResponse = "[" + senderId + "]: " + decryptedMsg + " [İmza Doğrulandi]";
                                } else {
                                    serverResponse = "[" + senderId + "]: " + decryptedMsg + " [İmza Doğrulanamadi!]";
                                }
                            } else {
                                decryptedMsg = Client.decryptMessage(msg, senderId);
                                serverResponse = "[" + senderId + "]: " + decryptedMsg;
                            }
                        } catch (Exception e) {
                            System.out.println("Şifre çözme veya imza doğrulama hatasi: " + e.getMessage());
                            serverResponse = "[" + senderId + "]: " + msg;
                        }
                    }
                }
              System.out.println("Sunucudan gelen mesaj: " + serverResponse);
               /*  counter++;
                if(counter==2)
                {
                     Client.setClientId(serverResponse);
                }*/
               
            }
        } catch (IOException e) {
            System.out.println("Sunucu bağlantisinda hata oluştu: " + e.getMessage());
        } finally {
            try {
                input.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
