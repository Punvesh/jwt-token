import java.util.scanner;
class fibo
{
public static void main(String[]args)
{
scanner s=new Scanner(System.in);
int n=s.nextInt();
int first=-1;
int second=1;
int next;
for (int i=1;i<=n;i++)
{
next=first+second;
first=second;
second=next;

system.out.println(next+" ");
}
}
}