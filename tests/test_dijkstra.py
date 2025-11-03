from pathfinding.dijkstra import dijkstra

# Mô hình mạng tấn công
# Node: hệ thống hoặc lỗ hổng
# Edge: kết nối giữa các điểm yếu
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