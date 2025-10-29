import java.util.Scanner;
class ArrayMethod3{
static void DisplayArray(int[] x){
System.out.println("Array Elements are: ");
for (int i=0;i<x.length;i++){
System.out.println(x[i]);
}
}
public static void main(String[] args){
Scanner sc=new Scanner(System.in);
int[]a=new int[5];
System.out.println("Enter the elements: ");
for (int i=0;i<a.length;i++){
a[i]=sc.nextInt();
}
DisplayArray(a);
}
}