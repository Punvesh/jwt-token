import java.util.Scanner;
class DigDivision{
public static void main(String[] args)
{
Scanner sc=new Scanner(System.in);
int n=sc.nextInt();
int org=n;
while(n>10)
{
int dig=n%10;
if(dig==0||(org%dig)!=0)
{
System.out.println("No");
return;
}
n=n/10;
}
System.out.println("Yes");
}
}