public class RootUtil {
    public int TonelliShanks(int p, int n) {
        // n is a quadratic residue
        if ((int) ((Math.pow(n, (p - 1) / 2))) % p != 1) {
            System.out.println("No roots");
        }
        //find max power of 2 dividing p-1
        int S = 0;
        while ((p - 1) % Math.pow(2, S) == 0) {
            S += 1;
        }
        S -= 1;
        // p-1 = Q * (2^s)
        int Q = (int) ((p - 1) / Math.pow(2, S));
        System.out.println("Q"+Q);
        // z is a non-residue quadratic modulo p
        int z = 1;
        int res = (int) (Math.pow(z, (p - 1) / 2)) % p;
        System.out.println("res"+res);
        while (res != p - 1) {
            z += 1;
            res = (int) (Math.pow(z, (p - 1) / 2)) % p;
        }
        int c = (int) (Math.pow(z, Q)) % p; //c
        int R = (int) (Math.pow(n, (Q + 1) / 2)) % p; //R
        int t = (int) (Math.pow(n, Q)) % p; //t
        int M = S;
        while (t % p != 1) {
            int i = 0;
            boolean div = false;
            while (div == false) {
                i += 1;
                t = (int) (Math.pow(t, 2)) % p;
                if (t % p == 1) {
                    div = true;
                }
            }
            int b = (int) (Math.pow(c, (int) (Math.pow(2, M - i - 1)))) % p;
            R = (R * b) % p;
            t = t * (int) ((Math.pow(b, 2))) % p;
            c = (int) (Math.pow(b, 2)) % p;
            M = i;
        }
        return R;
    }

    public static void main(String[] args) {
        RootUtil ru = new RootUtil();
        int root = ru.TonelliShanks(11, 9);
        System.out.println(root);
    }
}





