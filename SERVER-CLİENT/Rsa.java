//RSA algoritması ile public ve private anahtar çiftlerini üretir. Bu sınıf şifreleme ve şifre çözme işlemlerinde kullanılabilir.
import java.math.BigInteger;
import java.util.Random;

public class Rsa {
    private BigInteger p;
    private BigInteger q;
    private BigInteger N;
    private BigInteger Q;
    private BigInteger e;
    private BigInteger d;
    private int bitlength = 2048;
    private Random r;

    public Rsa() {
        r = new Random();
        // Büyük asal sayılar üret
        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);

        // Modül N ve Q değerlerini hesapla
        N = p.multiply(q);
        Q = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // e değeri seç ve aralarında asal kontrolü yap
        e = BigInteger.probablePrime(bitlength / 2, r);
        while (Q.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(Q) < 0) {
            e = e.add(BigInteger.ONE);
        }

        // d değerini hesapla (modüler ters)
        d = e.modInverse(Q);
    }

    public BigInteger getPublicKey() {
        return e;
    }

    public BigInteger getPrivateKey() {
        return d;
    }

    public BigInteger getN() {
        return N;
    }

}