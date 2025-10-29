class maxSubArraySum{
    public static void main(String[] args){
        int nums[]  = {11,22,33,44,55};
        int currentMax = nums[0];
        int maxSoFar = nums[0];
        for(int i = 0;i<nums.length;i++){
            currentMax = Math.max(nums[i],currentMax+nums[i]);
            maxSoFar = Math.max(maxSoFar,currentMax);
        }
        System.out.println("Max Sub Array Sum: "+maxSoFar);
    }
}