//Sunucunun istemcilerle birebir bağlantısını yönetir. Her istemci için ayrı bir thread olarak çalışır.
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;


public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private BufferedReader input;
    private PrintWriter output;
    private String clientId;
    private  static ArrayList<ClientHandler> clients;
    private String publicKey;
    private String N;
   

    public ClientHandler(Socket clientSocket,ArrayList<ClientHandler>clients) throws IOException {
        this.clientSocket = clientSocket;
        this.clients=clients;
        input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        output = new PrintWriter(clientSocket.getOutputStream(), true);
    }
   
    @Override
    public void run()   {

           
        try {

            publicKey = input.readLine().split(":")[1];
            N = input.readLine().split(":")[1];
            System.out.println("Açik Anahtar: " + publicKey);
            System.out.println("Modul: " + N);
            

            output.println("Kullanici adinizi belirleyin:");
            clientId = input.readLine();
            //output.println(clientId);
            Server.registerClient(clientId, this);
            output.println("Hoşgeldiniz, " + clientId + "!");
            ClientInfo clientInfo=new ClientInfo(publicKey, N);
            Server.InfoClient(clientId, clientInfo);

            String message;
            while ((message = input.readLine()) != null) {
                 if (message.startsWith("[kime:")) {
                    int endIndex = message.indexOf("]");
                    if (endIndex != -1) {
                        String targetClientId = message.substring(6, endIndex);
                        String msg = message.substring(endIndex + 1).trim();
                     try{
                        if (!Server.sessionKeys.containsKey(clientId + "-" + targetClientId) && 
                        !Server.sessionKeys.containsKey(targetClientId + "-" + clientId)) {
                        
                            Server.createAndDistributeSessionKey(clientId, targetClientId);
                        }
                        if(msg!="")
                        sendMessageToClient(targetClientId, msg); 
                    }
                        catch (Exception e) {
                            System.out.println("Session Key oluşturulamadi.");
                            e.getMessage();
                        }
                    
                        
                    }
                } 
                else if (message.equals("Bitti.")) {
                    output.println("Bağlanti sonlandiriliyor. Hoşçakal!");
                    break;
                } 
                else {
                    output.println("Geçersiz komut.");
                }
            }
        } 
        catch (IOException e) {
            System.out.println("Client handler hata oluştu: " + e.getMessage());
        } finally {
            cleanup();
        }
    }
  
    private void sendMessageToClient(String targetClientId, String msg) {
        ClientHandler targetClient = Server.getClient(targetClientId);
        if (targetClient != null) {
            if (msg.contains("[SIGNED]")) {
                // İmzalı mesaj için public key bilgisini ekle
                ClientInfo senderInfo = Server.getpublicKeyClientInfo(clientId);
                msg = msg + "[PUBKEY]" + senderInfo.getPublicKey() + ":" + senderInfo.getN();
            }
            targetClient.output.println("(" + clientId + "): " + msg);
            output.println("[" + clientId + "] --> [" + targetClientId + "]: " + msg);
        } else {
            output.println("Kullanici bulunamadi: " + targetClientId);
        }
    }
   
    public String getClientId(){
        return this.clientId;
    }
    public  void sendSessionKey(String encryptedKey, String targetId) {
        output.println("SESSION_KEY:" + encryptedKey + ":" + targetId);
    }

    private void cleanup() {
        try {
            input.close();
            output.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
 }

