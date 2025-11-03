import csv
import random
from pathfinding.k_shortest_paths import top_k_shortest_paths
from src.network_builder import create_sample_network
from .feature_extractor import extract_features

graph = create_sample_network()

# get top-k candidate paths
candidates = top_k_shortest_paths(graph, 'A', 'F', k=4)
shortest_len = len(candidates[0])

# Buid dataset
dataset = []
for path in candidates:
    features = extract_features(path, graph, shortest_len)
    features['label'] = random.choice([0, 1])
    features['path'] = path
    dataset.append(features)
    
# save to CSV
keys = dataset[0].keys()
with open('data/generated_paths.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=keys)
    writer.writeheader()
    writer.writerows(dataset)

print("Dataset saved to data/generated_paths.csv")