import java.util.Scanner;
class ArrayMethod2
{
static void ArrayDisplay(int[] x)
{
System.out.prinln("Array Elements are: ");
for(int i=0;i<x.length;i++)
{
System.out.prinln("x[i]");
}
}
public static void main(String[] args)
{
Scanner sc=new scanner(System.in);
int[]a= new int [5];
System.out.println("Enter the array elements");
for(int i=0;i<a.length;i++)
{
a[i]=sc.nextInt();
}
ArrayDisplay();
}
}