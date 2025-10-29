import java.util.Scanner;
class StrongNumber{
static int fact(int x)
{
int f=1;
for(int i=1;i<=x;i++)
{
f*=i;
}
return f;
}
public static void main(String[] args){
Scanner sc=new Scanner(System.in);
int n = sc.nextInt();
int sum=0;
int org=n;
while(n>0)
{
int dig=n%10;
sum=sum+fact(dig);
n=n/10;
}
if (org==sum){
System.out.println("StrongNumber");
}
else{
System.out.println("Not a StrongNumber");
}
}
}
