import java.util.*;
 import java.io.*;
 
public class BrickWall {
    static class Node implements Comparable<Node> {
        int cost, r, c;
        Node(int cost, int r, int c) {
            this.cost = cost;
            this.r = r;
            this.c = c;
        }
        public int compareTo(Node other) {
            return Integer.compare(this.cost, other.cost);
        }
    }
    
    public static void main(String[] args) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        int n = Integer.parseInt(br.readLine());
        String[] gridLines = new String[n];
        for (int i = 0; i < n; i++) {
            gridLines[i] = br.readLine();
        }
        
        // Parse input into unit grid
        List<List<Character>> unitGrid = new ArrayList<>();
        int unitWidth = 0;
        
        // First pass to determine unit width
        for (String line : gridLines) {
            int units = 0;
            int i = 0;
            while (i < line.length()) {
                if (Character.isDigit(line.charAt(i))) {
                    StringBuilder numStr = new StringBuilder();
                    while (i < line.length() && Character.isDigit(line.charAt(i))) {
                        numStr.append(line.charAt(i));
                        i++;
                    }
                    int length = Integer.parseInt(numStr.toString());
                    units += length;
                    i++; // skip the brick type
                } else {
                    units++;
                    i++;
                }
            }
            unitWidth = Math.max(unitWidth, units);
        }
        
        // Build unit grid
        for (String line : gridLines) {
            List<Character> row = new ArrayList<>();
            int i = 0;
            while (i < line.length()) {
                if (Character.isDigit(line.charAt(i))) {
                    StringBuilder numStr = new StringBuilder();
                    while (i < line.length() && Character.isDigit(line.charAt(i))) {
                        numStr.append(line.charAt(i));
                        i++;
                    }
                    int length = Integer.parseInt(numStr.toString());
                    char brickType = line.charAt(i);
                    i++;
                    for (int j = 0; j < length; j++) {
                        row.add(brickType);
                    }
                } else {
                    char brickType = line.charAt(i);
                    i++;
                    row.add(brickType);
                }
            }
            // Pad row to unitWidth if necessary
            while (row.size() < unitWidth) {
                row.add('R');
            }
            unitGrid.add(row);
        }
        
        // Find source and destination positions
        List<int[]> sources = new ArrayList<>();
        int[] dest = null;
        int rows = unitGrid.size();
        int cols = unitGrid.get(0).size();
        
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                char cell = unitGrid.get(i).get(j);
                if (cell == 'S') {
                    sources.add(new int[]{i, j});
                } else if (cell == 'D') {
                    dest = new int[]{i, j};
                }
            }
        }
        
        if (sources.isEmpty() || dest == null) {
            System.out.println(0);
            return;
        }
        
        // Dijkstra's algorithm from all sources
        int INF = Integer.MAX_VALUE;
        int[][] dist = new int[rows][cols];
        for (int i = 0; i < rows; i++) {
            Arrays.fill(dist[i], INF);
        }
        
        PriorityQueue<Node> pq = new PriorityQueue<>();
        for (int[] source : sources) {
            int sr = source[0], sc = source[1];
            dist[sr][sc] = 0;
            pq.offer(new Node(0, sr, sc));
        }
        
        int[][] directions = {{0, 1}, {1, 0}, {0, -1}, {-1, 0}};
        
        while (!pq.isEmpty()) {
            Node current = pq.poll();
            int cost = current.cost;
            int r = current.r;
            int c = current.c;
            
            if (r == dest[0] && c == dest[1]) {
                System.out.println(cost);
                return;
            }
            
            if (cost > dist[r][c]) {
                continue;
            }
            
            for (int[] dir : directions) {
                int nr = r + dir[0];
                int nc = c + dir[1];
                
                if (nr >= 0 && nr < rows && nc >= 0 && nc < cols) {
                    char cellType = unitGrid.get(nr).get(nc);
                    if (cellType == 'R') {
                        continue;
                    }
                    
                    int newCost = cost;
                    if (cellType == 'G') {
                        newCost = cost + 1;
                    }
                    // S and D have cost 0
                    
                    if (newCost < dist[nr][nc]) {
                        dist[nr][nc] = newCost;
                        pq.offer(new Node(newCost, nr, nc));
                    }
                }
            }
        }
        
        // If destination not reachable
        System.out.println(0);
    }
}