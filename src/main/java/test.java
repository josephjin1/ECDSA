

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECPoint;

public class test {
    private static ECDSA ecdsa = new ECDSA();
    private static PointMultiplication PM = new PointMultiplication();

    public static void main(String[] args) throws NoSuchAlgorithmException {
        BigInteger k1 = ecdsa.SelectK();
        BigInteger k2 = ecdsa.SelectK();
        /*ECPoint G1 = PM.AddPoint(ecdsa.G, ecdsa.G);
        ECPoint G2 = PM.DoublePoint(ecdsa.G);
        System.out.println(G1.getAffineX().toString());
        System.out.println(G2.getAffineX().toString());*/
        ECPoint G1 = PM.ScalarMulti(k1, ecdsa.G);
        ECPoint G2 = PM.ScalarMulti(k2, ecdsa.G);
        BigInteger x1 = G1.getAffineX();
        BigInteger y1 = G1.getAffineY();
        BigInteger x2 = G2.getAffineX();
        BigInteger y2 = G2.getAffineY();
        ECPoint G3 = PM.AddPoint(G1,G2);
        BigInteger x3 = G3.getAffineX();
        BigInteger y3 = G3.getAffineY();
        BigInteger A = x1.subtract(x2).pow(2).multiply(x3.pow(2));
        BigInteger tempB = x1.add(x2).multiply((x1.multiply(x2).add(ecdsa.key.a)));
        BigInteger B = tempB.add(ecdsa.key.b.multiply(new BigInteger("2"))).multiply(x3).multiply(new BigInteger("2"));
        BigInteger C1 = x1.multiply(x2).subtract(ecdsa.key.a).pow(2);
        BigInteger C2 = x1.add(x2).multiply(ecdsa.key.b).multiply(new BigInteger("4"));
        BigInteger result = A.subtract(B).add(C1).subtract(C2).mod(((ecdsa.key).p));
        System.out.println(G3.getAffineX());
        System.out.println("result:"+result.toString());

        BigInteger c = C1.add(C2);
        BigInteger a =  x1.subtract(x2).pow(2);
        BigInteger b = tempB.add(ecdsa.key.b.multiply(new BigInteger("2"))).multiply(new BigInteger("2")).negate();
        BigInteger delta = b.pow(2).subtract(new BigInteger("4").multiply(a).multiply(c));
        TonelliShanks TS = new TonelliShanks();
        TonelliShanks.Solution solution = TS.getTS(delta,ecdsa.key.p);
        System.out.println("root1:"+solution.root1);
        System.out.println("root2:"+solution.root2);
        BigInteger sqrtDelta = ecdsa.getSqrt(delta);
        BigInteger root1 = b.negate().add(sqrtDelta).multiply(a.multiply(new BigInteger("2")).modInverse(ecdsa.key.p)).mod(ecdsa.key.p);
        BigInteger root2 = b.negate().subtract(sqrtDelta).multiply(a.multiply(new BigInteger("2")).modInverse(ecdsa.key.p)).mod(ecdsa.key.p);
        BigInteger At = x1.subtract(x2).pow(2).multiply(root2.pow(2));
        BigInteger tempBt = x1.add(x2).multiply((x1.multiply(x2).add(ecdsa.key.a)));
        BigInteger Bt = tempB.add(ecdsa.key.b.multiply(new BigInteger("2"))).multiply(root2).multiply(new BigInteger("2"));
        BigInteger C1t = x1.multiply(x2).subtract(ecdsa.key.a).pow(2);
        BigInteger C2t = x1.add(x2).multiply(ecdsa.key.b).multiply(new BigInteger("4"));
        BigInteger resultt = At.subtract(Bt).add(C1t).subtract(C2t).mod(((ecdsa.key).p));
        System.out.println(resultt);
        System.out.println(root1);
        System.out.println(root2);
    }
}
