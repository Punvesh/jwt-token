public static void main(String[] args) 
{
    int[] arr = {22, 34, 55, 56, 56, 56, 88, 90};
    int j = 0;
        for (int i=1;i<=arr.length;i++){
            if (arr[i]!=arr[j]){
                j++;
                int temp = arr [j];
                arr[j]=arr[i];
                arr[i]=temp;
            }
        }
        for (int i=0;i<=j;i++){
            System.out.println(arr[i] + " ");
        }
}