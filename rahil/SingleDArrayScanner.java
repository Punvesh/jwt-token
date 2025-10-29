import java.util.*;
class SingleDArrayScanner{
public static void main(String[] args){
Scanner sc = new Scanner(System.in);
System.out.print("Enter the number of elements: ");
int n = sc.nextInt();
int arr[]=new int[n];
System.out.print("Enter the elements: ");
for(int i=0;i<arr.length;i++){
arr[i]=sc.nextInt();
System.out.print("Array elements are: "+arr[i]);
}
}
}