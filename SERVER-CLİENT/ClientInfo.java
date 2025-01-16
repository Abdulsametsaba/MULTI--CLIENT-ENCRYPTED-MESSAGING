

public class ClientInfo {
    private String publicKey;
    private String N;
    public ClientInfo(String publicKey,String N ){
        this.publicKey=publicKey;
        this.N=N;
    }
   
    public String getPublicKey(){
        return this.publicKey;
    }
    public String getN(){
        return this.N;
    }
    
}
