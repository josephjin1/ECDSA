
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.text.*;
import java.util.*;

public class Sum{
    // get the value of sextuple T = (p,a,b,G,n,h) in curve secp256k1
    public static GenerateKey key = new GenerateKey ();
    public static BigInteger N = key.N;
    public BigInteger p = key.p;
    public static BigInteger zero = BigInteger.ZERO;
    public static BigInteger one = BigInteger.ONE;
    public EllipticCurve curve = key.curve;
    public static ECPoint G = key.G;
    static NumberFormat formatter = new DecimalFormat("#0.00");
    PointMultiplication PM =new PointMultiplication ();
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
        //        +totalTime *1000 + "us");
        return Signature;
    }
    /**
     * This method calculates the hash value by using SHA -1 algorithm .
     */
    public BigInteger SHA1(byte [] m) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
        byte [] result = mDigest.digest(m);
        return new BigInteger(result);
    }

    public  HashSet<BigInteger> recursionSummationPolynomial(BigInteger[] rs){
        HashSet<BigInteger> Xi = new HashSet<BigInteger>();
        BigInteger[] parameters = new BigInteger[2];
        System.out.println("--------------recursion starts---------- ");
        if(rs.length > 3){
            BigInteger[] rs1 = new BigInteger[rs.length/2+1];
            System.arraycopy(rs,0,rs1,0,rs1.length-1);
            BigInteger[] rs2 = new BigInteger[rs.length/2+1];
            System.arraycopy(rs,rs.length/2,rs2,0,rs2.length-1);
            BigInteger X = new BigInteger("0");
            rs1[rs1.length-1]=X;
            HashSet<BigInteger> tempX = new HashSet<BigInteger>();

            tempX =  recursionSummationPolynomial(rs1);

            for(BigInteger possibleValue: tempX){
                rs2[rs2.length-1] = possibleValue;
                Xi.addAll(recursionSummationPolynomial(rs2));
            }

        }
        else if (rs.length == 3){
            int count = 0;
            for (BigInteger i: rs){
                if (i.compareTo(zero) != 0){
                    parameters[count] = i;
                    count++;
                }
            }
            Xi.addAll(computeXfromPoly3(parameters[0],parameters[1]));
        }
        return Xi ;
    }

    public HashSet<BigInteger> computeXfromPoly3(BigInteger r1, BigInteger r2){
        BigInteger A = r1.subtract(r2).pow(2);
        BigInteger B = (r1.add(r2)).multiply(r1.multiply(r2).add(new BigInteger("14"))).multiply(new BigInteger("2").negate());
        BigInteger C = (r1.multiply(r2)).pow(2).subtract((r1.add(r2)).multiply(new BigInteger("28"))).negate();
        BigInteger Delta = B.pow(2).subtract(A.multiply(C).multiply(new BigInteger("4")));
        HashSet<BigInteger> X = new HashSet<BigInteger>();
        if(Delta.compareTo(zero) != -1){
            BigInteger x1 = (B.negate().add(getSqrt(Delta))).divide(A.multiply(new BigInteger("2")));
            BigInteger x2 = (B.negate().subtract(getSqrt(Delta))).divide(A.multiply(new BigInteger("2")));
            X.add(x1);
            X.add(x2);
            System.out.println("x1:"+x1.toString());
            System.out.println("x2:"+x2.toString());
        }
        else{
            System.out.println("Parameter Error!");
        }
        return X;
    }

    public boolean summationPoly3(BigInteger[] rs){
        System.out.println("-----------compute f3-----------");
        BigInteger A = rs[0].subtract(rs[1]).mod(p).pow(2).mod(p);
        BigInteger B = (rs[0].add(rs[1]).mod(p)).multiply(rs[0].multiply(rs[1].mod(p)).add(new BigInteger("14"))).mod(p).multiply(new BigInteger("2").mod(p).negate());
        BigInteger C = (rs[0].multiply(rs[1]).mod(p)).pow(2).mod(p).subtract((rs[0].add(rs[1]).mod(p)).mod(p).multiply(new BigInteger("28"))).mod(p);
        BigInteger temp = A.multiply(rs[2].pow(2)).add(B.multiply(rs[2])).add(C);
       /* System.out.println("res:"+temp.toString());
        BigInteger A1 = (rs[0].subtract(rs[1])).pow(2).;
        BigInteger B1 = (rs[0].add(rs[1])).multiply(rs[0].multiply((rs[1])).add(new BigInteger("14"))).multiply(new BigInteger("2")).negate();
        BigInteger C1 = (rs[0].multiply(rs[1])).pow(2).subtract(rs[0].add(rs[1]).multiply(new BigInteger("28")));
        BigInteger temp1 = A1.multiply(rs[2].pow(2)).add(B1.multiply(rs[2])).add(C1);
        System.out.println(temp.toString());
        System.out.println(temp1.toString());*/
        if (temp.compareTo(zero) == 0){
            return true;
        }
        else {
            return false;
        }




    }

    public  boolean summationPolynomial(BigInteger[] rs){
        if (rs.length == 3){
            return summationPoly3(rs);
        }
        else if (rs.length > 3){
            BigInteger[] rs1 = new BigInteger[rs.length/2+1];
            BigInteger[] rs2 = new BigInteger[rs.length/2+1];
            System.arraycopy(rs,0,rs1,0,rs1.length-1);
            System.arraycopy(rs,rs.length/2,rs2,0,rs2.length-1);
            BigInteger X = new BigInteger("0");
            rs1[rs1.length-1]=X;
            rs2[rs2.length-1]=X;
            HashSet<BigInteger> resX1 = new HashSet<BigInteger>();
            HashSet<BigInteger> resX2 = new HashSet<BigInteger>();
            System.out.println("-----------rs1-------");
            for(BigInteger i:rs1){
                System.out.println(i.toString());
            }
            System.out.println("-----------rs2-------");
            for(BigInteger i:rs2){
                System.out.println(i.toString());
            }
            resX1 = recursionSummationPolynomial(rs1);
            resX2 = recursionSummationPolynomial(rs2);
            System.out.println("-----------resX1-------");
            for(BigInteger j:resX1){
                System.out.println(j.toString());
            }
            System.out.println("-----------resX2-------");
            for(BigInteger j:resX2){
                System.out.println(j.toString());
            }
            for(BigInteger index: resX1){
                if (resX2.contains(index)){
                    return true;
                }
            }

        }
        return false;
    }


    /**
     * This method verifies a signature on message m given the public key.
     */
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
     * This method verifies a batch of signatures.
     */
    public void batchVerif(byte[] m, ArrayList<BigInteger[]> signatures, ArrayList<ECPoint> pks) throws NoSuchAlgorithmException{
        Long startTime = System.currentTimeMillis();
        BigInteger sumU = new BigInteger("0");

        ECPoint temp = new ECPoint(zero, zero);//改无穷点
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
            temp = PM.AddPoint(temp, p2);
        }
        ECPoint p1 = PM.ScalarMulti(sumU, G);
        ECPoint pt = PM.AddPoint(p1, temp);
        BigInteger R = pt.getAffineX().mod(N);
        ArrayList<BigInteger> roots = new ArrayList<BigInteger>();
        BigInteger begin1 = new BigInteger("0");
        BigInteger begin2 = new BigInteger("0");
        for(int i = 0; i < signatures.size(); i++){
            BigInteger[] signature = signatures.get(i);
            BigInteger b = new BigInteger("7");
            BigInteger y1 = signature[0].multiply(signature[0]).multiply(signature[0]).add(b);
            BigInteger y2 = (BigInteger.ZERO).subtract(y1); //取相反数
            roots.add(y1);
            roots.add(y2);
            if(i == 0){
                begin1 = y1;
                begin2 = y2;
            }
        }
        if(dfs(begin1, roots, signatures, new ECPoint(zero, zero), 0, R) || dfs(begin2, roots, signatures, new ECPoint(zero, zero), 0, R) ){
            System.out.println("Valid signature");
        }
        else System.out.println("InValid signature");
    }
    //递归遍历所有根
    private static boolean dfs(BigInteger current, ArrayList<BigInteger> roots, ArrayList<BigInteger[]> signatures, ECPoint sumP, int height, BigInteger R){
        PointMultiplication PM =new PointMultiplication ();
        if(height == signatures.size()-1){
            return sumP.getAffineX().equals(R);
        }
        ECPoint cur = new ECPoint(signatures.get(height)[0], current);
        sumP = PM.AddPoint(sumP, cur);
        return dfs(roots.get(2*height), roots, signatures, sumP, height+1, R) || dfs(roots.get(2*height+1), roots, signatures, sumP, height+1, R);

    }
    //BigInteger开方 https://blog.csdn.net/mgl934973491/article/details/70337969/
    private static BigInteger getSqrt(BigInteger num) {
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


    public static void main(String[] arg) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        Sum ecdsa = new Sum();
        String message = "naive test";
        byte[] ms = message.getBytes();
 /*       BigInteger[] keyPair = key.KeyGeneration();
        BigInteger privateKey = keyPair[0];
        ECPoint publickey = new ECPoint(keyPair[1], keyPair[2]);
        BigInteger[] signature = ecdsa.Sign(ms, privateKey);
        ecdsa.verify(ms, signature , publickey);*/
        PointMultiplication PM =new PointMultiplication ();
        ArrayList<BigInteger[]> signatures = new ArrayList<BigInteger[]>();
        BigInteger[] rs = new BigInteger[3];
        ArrayList<ECPoint> pks = new ArrayList<ECPoint>();
        /****************************************
         *
         */
        BigInteger k1 = ecdsa.SelectK();
        BigInteger k2 = ecdsa.SelectK();
        ECPoint p1 = PM.ScalarMulti(k1,G);
        ECPoint p2 = PM.ScalarMulti(k2,G);
        ECPoint p3 = PM.AddPoint(p1,p2);
        ecdsa.computeXfromPoly3(p1.getAffineX(),p2.getAffineX());
        System.out.println("p3:"+p3.getAffineX().toString());
        rs = new BigInteger[]{p1.getAffineX(), p2.getAffineX(), p3.getAffineX()};
        if(ecdsa.summationPoly3(rs) == true){
            System.out.println("final");
        }
        else {
            System.out.println("Ooooops!");
        }
        /********************************
         *
         */
       /* System.out.println("rs:");
        for(int i = 0 ; i < 2; i++){
            BigInteger[] keyPair = key.KeyGeneration();
            BigInteger privatekey = keyPair[0];
            ECPoint publickey = new ECPoint(keyPair[1], keyPair[2]);
            BigInteger[] signature = ecdsa.Sign(ms,privatekey);
            rs[i] = signature[0];
            System.out.println(i+":"+rs[i].toString());
            pks.add(publickey);
            signatures.add(signature);
        }
        BigInteger sumU = new BigInteger("0");

        ECPoint temp = new ECPoint(zero, zero);//改无穷点
        for(int i = 0; i < signatures.size(); i++){
            BigInteger[] signature = signatures.get(i);
            if (signature [0]. compareTo(N) == 1 || signature [0]. compareTo(one) ==
                    -1
                    || signature [1]. compareTo(N) == 1
                    || signature [1]. compareTo(one) == -1) {
                System.out.println("SIGNATURE WAS NOT IN VALID RANGE");
            }
            BigInteger w = signature[1].modInverse(N);//模乘逆元
            BigInteger h = ecdsa.SHA1(ms);
            BigInteger u = (h.multiply(w)).mod(N);
            BigInteger v = (signature [0]. multiply(w)).mod(N);
            sumU = sumU.add(u);
            //ECPoint p1 = PM.ScalarMulti(u, G);// G = P
            ECPoint Q = pks.get(i);
            ECPoint p2 = PM.ScalarMulti(v, Q);
            temp = PM.AddPoint(temp, p2);
        }
        ECPoint p1 = PM.ScalarMulti(sumU, G);
        ECPoint pt = PM.AddPoint(p1, temp);
        BigInteger R = pt.getAffineX().mod(N);
        rs[2] = R;
        System.out.println("2:"+rs[2].toString());
        if(ecdsa.summationPolynomial(rs)){
            System.out.println("yes!");
        }
          */
    }




    /**
     * This method generates a signature , verifies it and calculate the running
     * time of the whole process.
     */
   /* public static void main(String [] arg) throws NoSuchAlgorithmException ,
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

        int [] a = {1,2,3,4,5};
        int [] b = new int[3];
        System.arraycopy(a,0,b,0,3);
        for (int i=0; i<b.length;i++){
            System.out.print(b[i]+" ");
        }
        System.out.println("");
        a[0] =6;
        a[1] =6;
        for (int i=0; i<b.length;i++){
            System.out.print(b[i]+" ");
        }
        System.out.println("");
        for (int i=0; i<a.length;i++){
            System.out.print(a[i]+" ");
        }


        List<String> list1 = new ArrayList<String>();
        List<String> list2 = new ArrayList<String>();
        list1.add("a");
        list1.add("b");
        list1.add("c");
        list1.add("d");
        list2.add("d");
        list2.add("f");
        list2.add("g");
        list2.add("h");
        list2.add("k");
        list2.addAll(list1);
        HashMap<String,Integer> mapList=new HashMap<String,Integer>();
        for(String str:list2){
            int count=0;
            if(mapList.get(str)!=null){
                count=mapList.get(str)+1;
            }
            mapList.put(str,count);
        }
        System.out.println("重复的元素是：");
        for(String key:mapList.keySet()){
            if(mapList.get(key)!=null && mapList.get(key)>0){
                System.out.println(key);
            }
        }

    }
    */
}


