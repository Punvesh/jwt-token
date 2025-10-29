import java.util.Scanner;
class ArrayMethod4
{
static int[] DisplayArray(int[] x)
{
return x;
}
public static void main(String[] args)
{
Scanner sc=new Scanner(System.in);
int[]a=new int[5];
System.out.println("Enter the elements: ");
for (int i=0;i<a.length;i++)
{
a[i]=sc.nextInt();
}
int[] y=DisplayArray(a);
System.out.println("Array Elements are: ");
for(int j=0;j<a.length;j++){
System.out.println(a[j]);
}
}

}