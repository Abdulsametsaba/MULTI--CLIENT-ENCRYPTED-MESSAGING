// Sunucu tarafındaki ana sınıftır. İstemcilerle bağlantıyı yönetir, istemcilerin public key'lerini kaydeder ve istemciler arasında iletişim sağlar.

import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.HashMap;





public class Server {
    private static int port = 5003;

    private static HashMap<String, ClientHandler> clientMap = new HashMap<>();
    private static HashMap<String,ClientInfo> clientInfo=new HashMap<>();
    public static HashMap<String, SecretKey> sessionKeys = new HashMap<>();

    private static ExecutorService pool = Executors.newFixedThreadPool(3);
    private  static ArrayList<ClientHandler> clients=new ArrayList<>();
    public  static ArrayList<ClientHandler> getClients(){
        return clients;
    }
   


    public static void main(String[] args) throws IOException {
        ServerSocket server = new ServerSocket(port);
        System.out.println("Sunucu başlatildi. Client bağlantilari bekleniyor...");

        while (true) {
            Socket clientSocket = server.accept();
            System.out.println("Yeni bir client bağlandi.");
            ClientHandler clientThread = new ClientHandler(clientSocket,clients);
            clients.add(clientThread);
            pool.execute(clientThread);
        }
    }
  //Java Senkronizasyonu, belirli bir zamanda yalnızca bir iş parçacığının kaynağa erişebilmesini sağlamak için bazı senkronizasyon yöntemleriyle kullanılır. 
    public static synchronized void registerClient(String clientId, ClientHandler handler) {
        clientMap.put(clientId, handler);
    }

    public static synchronized void createAndDistributeSessionKey(String client1, String client2) throws Exception {
        String sessionId1 = client1 + "-" + client2;
        String sessionId2 = client2 + "-" + client1;
    
    if (sessionKeys.containsKey(sessionId1) || sessionKeys.containsKey(sessionId2)) {
        System.out.println("Session key zaten mevcut");
        return;
    }

        // AES session key oluştur
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey sessionKey = keyGen.generateKey();
        // Session key'i sakla
        sessionKeys.put(sessionId1, sessionKey);
        sessionKeys.put(sessionId2, sessionKey);

        // Her iki client'a session key'i gönder
        String encodedKey = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
        // Client1'e gönder
        ClientInfo client1Info = getpublicKeyClientInfo(client1);
        if (client1Info == null) {
        System.out.println("Client1 bilgisi bulunamadi: " + client1);
        return;
        }
    
    // Client2'ye gönder
       ClientInfo client2Info = getpublicKeyClientInfo(client2);
       if (client2Info == null) {
        System.out.println("Client2 bilgisi bulunamadi: " + client2);
        return;
         }
        try {
            BigInteger encryptedKey1 = new BigInteger(encodedKey.getBytes())
                .modPow(new BigInteger(client1Info.getPublicKey()), new BigInteger(client1Info.getN()));
            getClient(client1).sendSessionKey(encryptedKey1.toString(), client2);
    
            BigInteger encryptedKey2 = new BigInteger(encodedKey.getBytes())
                .modPow(new BigInteger(client2Info.getPublicKey()), new BigInteger(client2Info.getN()));
            getClient(client2).sendSessionKey(encryptedKey2.toString(), client1);
    
            System.out.println("Session key başariyla dağitildi");
        } catch (Exception e) {
            System.out.println("Session key dağitiminda hata: " + e.getMessage());
            throw e;
        }
    }

    

    public static synchronized ClientHandler getClient(String clientId) {
        return clientMap.get(clientId);
    }

    public static synchronized void InfoClient(String clientId, ClientInfo info) {
        clientInfo.put(clientId, info);
    }

    public static synchronized ClientInfo getpublicKeyClientInfo(String clientId) {
        return clientInfo.get(clientId);
    }


    

}

