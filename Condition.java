import java.util.*;

public class Condition{
    public static void main(String[] args){
        Scanner sc = new Scanner(System.in);
        int button = sc.nextInt();



        /*int a = sc.nextInt();
        int b = sc.nextInt();  
        if (a == b){
            System.out.println("a equals to b");
        }else if (a > b) {
            System.out.println("a is greater than b");
        }else {
            System.out.println("a is lesser than b");
        }*/

        switch(button){
            case 1 : System.out.println("hi");
            break;
            case 2 : System.out.println("hello");
            break;
            case 3 : System.out.println("yo!");
            break;
            default : System.out.println("Invalid button");
        }
    }
}