import java.util.Comparator;
import java.util.HashMap;
import java.util.PriorityQueue;

public class Main {
    class Country{
        public String name;
        public int scoce;
        public int winGoal;

        public Country(String name, int scoce, int winGoal) {
            this.name = name;
            this.scoce = scoce;
            this.winGoal = winGoal;
        }
        public void win(){
            this.scoce=this.scoce+3;
        }
    }

    public static void main(String[] args) {
        //构造最大堆
        PriorityQueue<Country> maxHeap = new PriorityQueue<>(new Comparator<Country>() {
            @Override
            //重写比较器
            public int compare(Country o1, Country o2) {
                if(o1.scoce == o2.scoce){
                    return o2.winGoal- o1.winGoal;
                }
                return o2.scoce-o1.scoce;
            }
        });
        HashMap<String,Country> map = new HashMap<String,Country>();
        //法国10:1中国
        while(true){
            Country matchCountry1 = map.get("法国");
            Country matchCountry2 = map.get("中国");
            maxHeap.remove(matchCountry2);
            maxHeap.remove(matchCountry1);
            matchCountry1.win();
            matchCountry2.lose();
            maxHeap.add(matchCountry2);
            maxHeap.add(matchCountry1);
        }

    }
}
