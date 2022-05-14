import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Identification {
    public static GenerateKey key = new GenerateKey ();
    public BigInteger N = key.N;
    public static BigInteger p = key.p;
    public BigInteger zero = BigInteger.ZERO;
    public BigInteger one = BigInteger.ONE;
    public EllipticCurve curve = key.curve;
    public ECPoint G = key.G;
    public static String message = "naive test";
    public static byte[] m = message.getBytes();
    PointMultiplication PM = new PointMultiplication();
    public BigInteger SHA1(byte [] m) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte [] result = mDigest.digest(m);
        return new BigInteger(result);
    }
    public boolean verify(byte [] m, BigInteger [] signature ,
                       ECPoint publickey) throws NoSuchAlgorithmException {
        Long startTime = System.currentTimeMillis ();
        // if R and S is not in [1,n -1] , signature invalid.
        if (signature [0]. compareTo(N) == 1 || signature [0]. compareTo(one) ==
                -1
                || signature [1]. compareTo(N) == 1
                || signature [1]. compareTo(one) == -1) {
            System.out.println("SIGNATURE WAS NOT IN VALID RANGE");
        }
        // calculate w = S^-1 mod N
        BigInteger w = signature [1]. modInverse(N);
        BigInteger h = SHA1(m);
        // calculate u1= hw mod N and u2=Rw mod N
        BigInteger u1 = (h.multiply(w)).mod(N);
        BigInteger u2 = (signature [0]. multiply(w)).mod(N);
        // calculate the curve point (x1 ,x2)=u1*G+u2* publicKey
        ECPoint p1 = PM.ScalarMulti(u1 , G);
        ECPoint p2 = PM.ScalarMulti(u2 , publickey);
        ECPoint pt = PM.AddPoint(p1 , p2);
        // calculate V = x1 mod N
        BigInteger V = pt.getAffineX ().mod(N);
        // if R=V, signature valid , otherwise invalid

        if (V.equals(signature [0]))
        {
            Long endTime = System.currentTimeMillis ();
            Long totalTime = endTime - startTime;
            System.out.println("Runing Time of verification:"
                    + totalTime + "ms");
            System.out.println("Valid signature");
            return true;
        }
        else
        {
            Long endTime = System.currentTimeMillis ();
            Long totalTime = endTime - startTime;
            System.out.println("Runing Time of verification:"
                    + totalTime + "ms");
            System.out.println("Invalid signature");
            return false;
        }

    }
    public Map<BigInteger[], ECPoint> individualTest(byte[] m, ArrayList<BigInteger[]> signatures, ArrayList<ECPoint> pks) throws NoSuchAlgorithmException {
        //List<BigInteger[]> invalidSignatuers = new ArrayList<BigInteger[]>();
        Long startTime = System.currentTimeMillis ();
        Map<BigInteger[], ECPoint> invalidSignatuers = new HashMap<BigInteger[], ECPoint>();
        for(int i = 0; i < pks.size(); i++){
            if(verify(m, signatures.get(i), pks.get(i)) == false){
                invalidSignatuers.put(signatures.get(i), pks.get(i));
            }
        }
        Long endTime = System.currentTimeMillis ();
        Long totalTime = endTime - startTime;
        System.out.println("Runing Time of individual Identification:"
                + totalTime + "ms");
        return invalidSignatuers;
    }
}
