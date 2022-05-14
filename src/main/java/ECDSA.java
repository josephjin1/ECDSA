
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
//import sun.security.ec.ECPrivateKeyImpl;
//import sun.security.ec.ECPublicKeyImpl;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.text.*;
import java.util.*;

public class ECDSA {
    // get the value of sextuple T = (p,a,b,G,n,h) in curve secp256k1
    public static GenerateKey key = new GenerateKey ();
    public BigInteger N = key.N;
    public static BigInteger p = key.p;
    public BigInteger zero = BigInteger.ZERO;
    public BigInteger one = BigInteger.ONE;
    public EllipticCurve curve = key.curve;
    public ECPoint G = key.G;
    static NumberFormat formatter = new DecimalFormat("#0.00");
    PointMultiplication PM =new PointMultiplication ();
    static TonelliShanks TS = new TonelliShanks();
    //TonelliShanks.Solution s = TS.getTS(zero, one);
    public static int count = 0;
    /**
     * This method generates a secure random number k in [1,n -1].
     */
    public BigInteger SelectK () throws NoSuchAlgorithmException {
        SecureRandom sr = new SecureRandom ();
        BigInteger K = new BigInteger (256 , sr);
        K = K.mod(N.subtract(one));
        while (K.equals(zero) || !(K.gcd(p).compareTo(one) == 0)) {
            K = new BigInteger (256 , sr);
            K = K.mod(N.subtract(one));
        }
        return K;
    }
    /*
        * This method signs a message m given the private key.
    */
    public BigInteger [] Sign(byte [] m, BigInteger privatekey)
            throws NoSuchAlgorithmException {
        Long startTime = System.currentTimeMillis ();
        BigInteger K = SelectK ();
        BigInteger dm = SHA1(m);
    // calculate the public key curve point Q.
        ECPoint Q = PM.ScalarMulti(K, G);
    // calculate R = x_q mod N
        BigInteger R = Q.getAffineX ().mod(N);


        BigInteger X = Q.getAffineX();
        BigInteger Y = Q.getAffineY();

        BigInteger temp0 = X.pow(3).add(new BigInteger("7")).mod(p);

        BigInteger temp1 = Y.pow(2).mod(p);

        BigInteger temp2 = (p.subtract(Y)).pow(2).mod(p);
        BigInteger temp = getSqrt(temp0);

        BigInteger temp3 = temp.pow(2).mod(p);
        BigInteger temp4 = p.subtract(temp).pow(2).mod(p);


    // calculate S = k^-1 (dm + R* privateKey ) mod N
        BigInteger Kin = K.modInverse(N);
        BigInteger mm = dm.add(privatekey.multiply(R));
        BigInteger S = (Kin.multiply(mm)).mod(N);
    // if R or S equal to zero , resign the message
        if (R.equals(zero) || S.equals(zero)) {
            K = SelectK ();
            Q = PM.ScalarMulti(K, G);
            R = Q.getAffineX ().mod(N);
            Kin = K.modInverse(N);
            mm = dm.add(privatekey.multiply(R));
            S = (Kin.multiply(mm)).mod(N);
        }
        BigInteger [] Signature = { R, S };
        Long endTime = System.currentTimeMillis ();
        Long totalTime = endTime - startTime;
        //System.out.println("Runing Time of singning in ECDSA:"
        //       +totalTime *1000 + "us");
        return Signature;
    }
    /**
     * This method calculates the hash value by using SHA -1 algorithm .
     */
    public BigInteger SHA1(byte [] m) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte [] result = mDigest.digest(m);
        return new BigInteger(result);
    }
    /**
     * This method verifies a signature on message m given the public key.
     */
    public void batchVerif(byte[] m, ArrayList<BigInteger[]> signatures, ArrayList<ECPoint> pks) throws NoSuchAlgorithmException{
        Long startTime = System.currentTimeMillis();
        BigInteger sumU = new BigInteger("0");
        ECPoint temp = new ECPoint(zero,zero);
        for(int i = 0; i < signatures.size(); i++){
            BigInteger[] signature = signatures.get(i);
            if (signature [0]. compareTo(N) == 1 || signature [0]. compareTo(one) ==
                    -1
                    || signature [1]. compareTo(N) == 1
                    || signature [1]. compareTo(one) == -1) {
                System.out.println("SIGNATURE WAS NOT IN VALID RANGE");
            }
            BigInteger w = signature[1].modInverse(N);//模乘逆元
            BigInteger h = SHA1(m);
            BigInteger u = (h.multiply(w)).mod(N);
            BigInteger v = (signature [0]. multiply(w)).mod(N);
            sumU = sumU.add(u);
            //ECPoint p1 = PM.ScalarMulti(u, G);// G = P
            ECPoint Q = pks.get(i);
            ECPoint p2 = PM.ScalarMulti(v, Q);
            if(i == 0) temp = p2;
            else{
                temp = PM.AddPoint(temp, p2);
            }
        }
        //批验证核心代码
        ECPoint p1 = PM.ScalarMulti(sumU, G);
        ECPoint pt = PM.AddPoint(p1, temp);
        BigInteger R = pt.getAffineX().mod(N);
        ArrayList<BigInteger> roots = new ArrayList<BigInteger>();
        BigInteger begin1 = new BigInteger("0");
        BigInteger begin2 = new BigInteger("0");
        for(int i = 0; i < signatures.size(); i++){
            BigInteger[] signature = signatures.get(i);
            BigInteger b = new BigInteger("7");
            BigInteger yPow = signature[0].pow(3).add(b);
            TonelliShanks.Solution solution = TS.getTS(yPow, key.p);
            roots.add(solution.root1);
            roots.add(solution.root2);
            if(i == 0){
                begin1 = solution.root1;
                begin2 = solution.root2;
            }
        }
        if(dfs(roots, signatures, new ECPoint(signatures.get(0)[0], begin1), 1, R) || dfs(roots, signatures, new ECPoint(signatures.get(0)[0], begin2), 1, R) ){
            System.out.println("Valid signature");
            Long endTime = System.currentTimeMillis ();
            Long totalTime = endTime - startTime;
            System.out.println("Runing Time of verification:"
                    + formatter.format(totalTime) + "ms");
        }
        else {
            System.out.println("InValid signature");
            Long endTime = System.currentTimeMillis ();
            Long totalTime = endTime - startTime;
            System.out.println("Runing Time of verification:"
                    + formatter.format(totalTime) + "ms");
        }
        System.out.println("the number of valid signatures:"+count);
    }
    //递归遍历所有根
    private boolean dfs(ArrayList<BigInteger> roots, ArrayList<BigInteger[]> signatures, ECPoint sumP, int height, BigInteger R){
        PointMultiplication PM =new PointMultiplication ();
        if(height == signatures.size()){
            ECDSA.count++;
            System.out.println("sump:"+sumP.getAffineX());
            return sumP.getAffineX().equals(R);
        }
        ECPoint cur1 = new ECPoint(signatures.get(height)[0], roots.get(height*2));
        //递归遍历求和多项式二叉树所有根
        ECPoint cur2 = new ECPoint(signatures.get(height)[0], roots.get(height*2+1));
        ECPoint sumP1 = PM.AddPoint(sumP, cur1);
        ECPoint sumP2 = PM.AddPoint(sumP, cur2);
        return dfs(roots, signatures, sumP1, height+1, R) || dfs(roots, signatures, sumP2, height+1, R);

    }

    //BigInteger开方 https://blog.csdn.net/mgl934973491/article/details/70337969/
    public BigInteger getSqrt(BigInteger num) {
        String s = num.toString();
        int mlen = s.length();    //被开方数的长度
        int len;    //开方后的长度
        BigInteger beSqrtNum = new BigInteger(s);//被开方数
        BigInteger sqrtOfNum;    //存储开方后的数
        BigInteger sqrtOfNumMul;    //开方数的平方
        String sString;//存储sArray转化后的字符串
        if (mlen % 2 == 0) len = mlen / 2;
        else len = mlen / 2 + 1;
        char[] sArray = new char[len];
        Arrays.fill(sArray, '0');//开方数初始化为0
        for (int pos = 0; pos < len; pos++) {
            //从最高开始遍历数组，
            //每一位都转化为开方数平方后刚好不大于被开方数的程度
            for (char ch = '1'; ch <= '9'; ch++) {
                sArray[pos] = ch;
                sString = String.valueOf(sArray);
                sqrtOfNum = new BigInteger(sString);
                sqrtOfNumMul = sqrtOfNum.multiply(sqrtOfNum);
                if (sqrtOfNumMul.compareTo(beSqrtNum) == 1) {
                    sArray[pos] -= 1;
                    break;
                }
            }
        }
        return new BigInteger(String.valueOf(sArray));
    }
    public void verify(byte [] m, BigInteger [] signature ,
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
            System.out.println("Valid signature");
        else
            System.out.println("Invalid signature");
        Long endTime = System.currentTimeMillis ();
        Long totalTime = endTime - startTime;
        System.out.println("Runing Time of verification:"
                + formatter.format(totalTime) + "ms");
    }
    /**
     * This method generates a signature , verifies it and calculate the running
     * time of the whole process.
     */
/*    public static void main(String [] arg) throws NoSuchAlgorithmException ,
            InvalidAlgorithmParameterException , NoSuchProviderException {
        ECDSA ecdsa = new ECDSA ();
        //Format format = new Format();
        String message = "ECDSA TEST";
        byte [] m = message.getBytes ();
        BigInteger [] keypair = key.KeyGeneration ();
        BigInteger privatekey = keypair [0];
        ECPoint publickey = new ECPoint(keypair [1], keypair [2]);
        System.out.println("private key is: " + privatekey.toString (16));
        //System.out.println("The private key is: "
        //        + format.format(privatekey.toByteArray ()));
        System.out.println("The private key is: "
                + privatekey.toByteArray ());
        System.out.println("x of public key is: "
                + publickey.getAffineX ().toString ());
        System.out.println("y of public key is: "
                + publickey.getAffineY ().toString ());
        BigInteger [] signature = ecdsa.Sign(m, privatekey);
        System.out.println("the value of R is:" + signature [0]);
        System.out.println("the value of S is:" + signature [1]);
        ecdsa.verify(m, signature , publickey);
    }*/
    //
    //递归求解求和多项式核心代码
    public HashSet<BigInteger> recursionSummationPolynomial(BigInteger[] rs) {
        HashSet<BigInteger> Xi = new HashSet<BigInteger>();
        BigInteger[] parameters = new BigInteger[2];
        System.out.println("--------------recursion starts---------- ");
        if (rs.length > 3) {
            BigInteger[] rs1 = new BigInteger[rs.length / 2 + 1];
            System.arraycopy(rs, 0, rs1, 0, rs1.length - 1);
            BigInteger[] rs2;
            if(rs.length % 2 == 1){
                rs2 = new BigInteger[rs.length / 2 + 2];
            }
            else{
                rs2 = new BigInteger[rs.length / 2 + 1];
            }
            // rs2 = new BigInteger[rs.length / 2 + 1];
            System.arraycopy(rs, rs.length / 2, rs2, 0, rs2.length-1);
            BigInteger X = new BigInteger("0");
            rs1[rs1.length - 1] = X;
            for (BigInteger i : rs1) {
                System.out.println(i.toString());
            }
            HashSet<BigInteger> tempX = new HashSet<BigInteger>();
            tempX = recursionSummationPolynomial(rs1);
            for (BigInteger possibleValue : tempX) {
                rs2[rs2.length - 1] = possibleValue;
                System.out.println("-----------recursionSummationPolynomial(rs2)-------");
                Xi.addAll(recursionSummationPolynomial(rs2));
            }

        } else if (rs.length == 3) {
            int count = 0;
            for (BigInteger i : rs) {
                if (i.compareTo(zero) != 0) {
                    System.out.println("count:"+count);
                    parameters[count] = i;
                    count++;
                }
            }
            System.out.println("p0:"+parameters[0]);
            System.out.println("p1:"+parameters[1]);
            Xi.addAll(computeXfromPoly3(parameters[0], parameters[1]));
        }
        return Xi;
    }

    //计算求和多项式核心代码
    public HashSet<BigInteger> computeXfromPoly3(BigInteger x1, BigInteger x2) {
        System.out.println("----------------------computeXfromPoly3----------------------");
        BigInteger A = x1.subtract(x2).pow(2);
        BigInteger tempB = x1.add(x2).multiply((x1.multiply(x2).add(key.a)));
        BigInteger B = tempB.add(key.b.multiply(new BigInteger("2"))).multiply(new BigInteger("2")).negate();
        BigInteger C1 = x1.multiply(x2).subtract(key.a).pow(2);
        BigInteger C2 = x1.add(x2).multiply(key.b).multiply(new BigInteger("4"));
        BigInteger C = C1.subtract(C2);
        HashSet<BigInteger> X = new HashSet<BigInteger>();
        BigInteger right = B.pow(2).multiply(A.pow(2).multiply(new BigInteger("4")).modInverse(key.p)).subtract(C.multiply(A.modInverse(key.p))).mod(key.p);
        TonelliShanks.Solution solution = TS.getTS(right, key.p);
        BigInteger b2a = B.multiply(A.multiply(new BigInteger("2")).modInverse(key.p));
        System.out.println("r1:" + solution.root1.subtract(b2a).mod(key.p).toString());
        System.out.println("r2:" + solution.root2.subtract(b2a).mod(key.p).toString());
        X.add(solution.root1.subtract(b2a).mod(key.p));
        X.add(solution.root2.subtract(b2a).mod(key.p));
        return X;
    }

    public boolean summationPoly3(BigInteger[] rs) {
        System.out.println("-----------compute f3-----------");
        BigInteger A = rs[0].subtract(rs[1]).pow(2).multiply(rs[2].pow(2));
        BigInteger tempB = rs[0].add(rs[1]).multiply((rs[0].multiply(rs[1]).add(key.a)));
        BigInteger B = tempB.add(key.b.multiply(new BigInteger("2"))).multiply(rs[2]).multiply(new BigInteger("2"));
        BigInteger C1 = rs[0].multiply(rs[1]).subtract(key.a).pow(2);
        BigInteger C2 = rs[0].add(rs[1]).multiply(key.b).multiply(new BigInteger("4"));
        BigInteger result = A.subtract(B).add(C1).subtract(C2).mod((key.p));
        //System.out.println(result.toString());
        if (result.compareTo(zero) == 0) {
            System.out.println("yes");
            return true;
        } else {
            System.out.println("false");
            return false;
        }


    }
    //建立求和多项式核心代码
    public boolean summationPolynomial(BigInteger[] rs) {
        if (rs.length == 3) {
            return summationPoly3(rs);
        } else if (rs.length > 3) {
            BigInteger[] rs1 = new BigInteger[rs.length / 2 + 1];
            BigInteger[] rs2;
            if(rs.length % 2 == 1){
                rs2 = new BigInteger[rs.length / 2 + 2];
            }
            else{
                rs2 = new BigInteger[rs.length / 2 + 1];
            }
            System.arraycopy(rs, 0, rs1, 0, rs1.length - 1);
            System.arraycopy(rs, rs.length / 2, rs2, 0, rs2.length - 1);
            BigInteger X = new BigInteger("0");
            rs1[rs1.length - 1] = X;
            rs2[rs2.length - 1] = X;
            HashSet<BigInteger> resX1 = new HashSet<BigInteger>();
            HashSet<BigInteger> resX2 = new HashSet<BigInteger>();
            System.out.println("-----------rs1-------");
            for (BigInteger i : rs1) {
                System.out.println(i.toString());
            }
            System.out.println("-----------rs2-------");
            for (BigInteger i : rs2) {
                System.out.println(i.toString());
            }
            resX1 = recursionSummationPolynomial(rs1);
            resX2 = recursionSummationPolynomial(rs2);
            System.out.println("-----------resX1-------");
            for (BigInteger j : resX1) {
                System.out.println(j.toString());
            }
            System.out.println("-----------resX2-------");
            for (BigInteger j : resX2) {
                System.out.println(j.toString());
            }
            for (BigInteger index : resX1) {
                if (resX2.contains(index)) {
                    return true;
                }
            }

        }
        return false;
    }
    public BigInteger getR(byte[] m, ArrayList<BigInteger[]> signatures, ArrayList<ECPoint> pks) throws NoSuchAlgorithmException {
        BigInteger sumU = new BigInteger("0");
        ECPoint temp = new ECPoint(zero,zero);
        for(int i = 0; i < signatures.size(); i++){
            BigInteger[] signature = signatures.get(i);
            if (signature [0]. compareTo(N) == 1 || signature [0]. compareTo(one) ==
                    -1
                    || signature [1]. compareTo(N) == 1
                    || signature [1]. compareTo(one) == -1) {
                System.out.println("SIGNATURE WAS NOT IN VALID RANGE");
            }
            BigInteger w = signature[1].modInverse(N);//模乘逆元
            BigInteger h = SHA1(m);
            BigInteger u = (h.multiply(w)).mod(N);
            BigInteger v = (signature [0]. multiply(w)).mod(N);
            sumU = sumU.add(u);
            //ECPoint p1 = PM.ScalarMulti(u, G);// G = P
            ECPoint Q = pks.get(i);
            ECPoint p2 = PM.ScalarMulti(v, Q);
            if(i == 0) temp = p2;
            else{
                temp = PM.AddPoint(temp, p2);
            }
        }
        ECPoint p1 = PM.ScalarMulti(sumU, G);
        ECPoint pt = PM.AddPoint(p1, temp);
        BigInteger R = pt.getAffineX().mod(N);
        return R;
    }
    public static void main(String[] arg) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        ECDSA ecdsa = new ECDSA();
        String message = "naive test";
        byte[] ms = message.getBytes();
 /*     BigInteger[] keyPair = key.KeyGeneration();
        BigInteger privateKey = keyPair[0];
        ECPoint publickey = new ECPoint(keyPair[1], keyPair[2]);
        BigInteger[] signature = ecdsa.Sign(ms, privateKey);
        ecdsa.verify(ms, signature , publickey);*/
        ArrayList<BigInteger[]> signatures = new ArrayList<BigInteger[]>();
        ArrayList<ECPoint> pks = new ArrayList<ECPoint>();
        for(int i = 0 ; i < 1; i++){
            BigInteger[] keyPair = key.KeyGeneration();
            BigInteger privatekey = keyPair[0];
            ECPoint publickey = new ECPoint(keyPair[1], keyPair[2]);
            BigInteger[] signature = ecdsa.Sign(ms,privatekey);
            pks.add(publickey);
            signatures.add(signature);
            System.out.println(signature[0]);
        }
        Long startTime1 = System.currentTimeMillis ();
        System.out.println("startTime1:"+startTime1);
        ecdsa.batchVerif(ms, signatures, pks);
        Long endTime1 = System.currentTimeMillis ();
        System.out.println("endTime1:"+endTime1);
        Long totalTime1 = endTime1 - startTime1;
        System.out.println("time consumption of naive batch:"+totalTime1);


     /*   PointMultiplication PM = new PointMultiplication();
      *//*  BigInteger k1 = ecdsa.SelectK();
        BigInteger k2 = ecdsa.SelectK();
        ECPoint p1 = PM.ScalarMulti(k1,key.G);
        ECPoint p2 = PM.ScalarMulti(k2,key.G);
        ECPoint p3 = PM.AddPoint(p1,p2);
        BigInteger p1x = p1.getAffineX();
        BigInteger p2x = p2.getAffineX();
        BigInteger[] rs = new BigInteger[3];
        rs[0] = p1x;
        rs[1] = p2x;
        rs[2] = p3.getAffineX();*//*


        ecdsa.summationPoly3(rs);
        BigInteger C1 = rs[0].multiply(rs[1]).subtract(key.a).pow(2);
        BigInteger C2 = rs[0].add(rs[1]).multiply(key.b).multiply(new BigInteger("4"));
        BigInteger a = rs[0].subtract(rs[1]).pow(2);
        BigInteger b = rs[0].add(rs[1]).multiply(rs[0].multiply(rs[1]).add(key.a)).add(key.b.multiply(new BigInteger("2"))).multiply(new BigInteger("2").negate());
        BigInteger c = C1.subtract(C2);
        BigInteger right = b.pow(2).multiply(a.pow(2).multiply(new BigInteger("4")).modInverse(key.p)).subtract(c.multiply(a.modInverse(key.p))).mod(key.p);
        TonelliShanks TS = new TonelliShanks();
        TonelliShanks.Solution s = TS.getTS(right,ecdsa.key.p);
        BigInteger root3 = s.root1.negate();
        BigInteger root4 = s.root2.negate();
        BigInteger x1 = s.root1.subtract(b.multiply(a.multiply(new BigInteger("2")).modInverse(key.p)).mod(key.p));
        BigInteger x2 = s.root2.subtract(b.multiply(a.multiply(new BigInteger("2")).modInverse(key.p)).mod(key.p));
        //BigInteger x3 = root3.subtract(b.multiply(a.multiply(new BigInteger("2")).modInverse(key.p)).mod(key.p));
        //BigInteger x4 = root4.subtract(b.multiply(a.multiply(new BigInteger("2")).modInverse(key.p)).mod(key.p));

      *//*  BigInteger right1 = b.pow(2).divide(a.pow(2).multiply(new BigInteger("4"))).subtract(c.divide(a));
        System.out.println(right1);
        BigInteger root = ecdsa.getSqrt(right1);
        System.out.println(root);
        BigInteger x11 = root.subtract(b.divide(a.multiply(new BigInteger("2"))));
        BigInteger x22 = root.negate().subtract(b.divide(a.multiply(new BigInteger("2"))));
        System.out.println("root1:"+x11);
        System.out.println("root2:"+x22);*//*
        System.out.println("root1:"+x1.toString());
        System.out.println("root2:"+x2.toString());
        //System.out.println("root3:"+x3.toString());
        //System.out.println("root4:"+x4.toString());

        System.out.println("R:"+rs[2]);
        //System.out.println("R:"+R);
*//*        BigInteger[] rs1 = new BigInteger[3];
        rs1[0] = signatures.get(0)[0];
        rs1[1] = signatures.get(1)[0];
        rs1[2] = x1;
        ecdsa.summationPoly3(rs1);
        BigInteger[] rs2 = new BigInteger[3];
        rs2[0] = signatures.get(0)[0];
        rs2[1] = signatures.get(1)[0];
        rs2[2] = x2;
        ecdsa.summationPoly3(rs2);*//*
*/




    }





}
