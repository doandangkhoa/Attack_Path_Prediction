import heapq
import os

def dijkstra(graph, src, dst):
    dist = {node: float('inf') for node in graph} # initial value is INF for every nodes in graph
    dist[src] = 0
    parent = {src: None} # parent[src] = None
     
    # initialize min heap
    pq = [(0, src)] # (distance, node)
    
    while pq:
        current_dist, node = heapq.heappop(pq)
        
        # skip outdated elements
        if(current_dist > dist[node]):
            continue
        
        for neighbor, weight in graph[node].items():
            new_dist = current_dist + weight
            if dist[neighbor] > new_dist: # dv > du + w
                dist[neighbor] = new_dist
                heapq.heappush(pq, (new_dist, neighbor))
                parent[neighbor] = node
                
    # reconstruct path
    path = []
    node = dst
    while node is not None:
        path.append(node)
        node = parent[node]
    path.reverse()
    
    return path, dist[dst]
            
if __name__ == "__main__":
    # demo
    graph = {
         'A': {'B': 2, 'C': 5},
        'B': {'C': 1, 'D': 4},
        'C': {'D': 2, 'E': 3},
        'D': {'F': 1},
        'E': {'F': 5},
        'F': {}
    }
    path, cost = dijkstra(graph, 'A', 'F')
    print("Shortest attack path:", path)
    print("Total cost:", cost)
    