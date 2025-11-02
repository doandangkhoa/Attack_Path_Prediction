# 📘 Project: Hybrid Dijkstra + Machine Learning for Attack Path Prediction

## 🎯 Objective

Build a simulation system that:

* Uses **Dijkstra** to generate candidate attack paths.
* Uses **Machine Learning (Random Forest)** to predict the most likely attack path.

The system will:

1. Generate simulated attack path data.
2. Train a prediction model.
3. Compare results with traditional Dijkstra paths.

---

# 🗓️ 8-Week Schedule

## **Week 1 — Setup & Fundamentals**

**Day 1:**

* Install Python and libraries: `networkx`, `pandas`, `scikit-learn`, `matplotlib`, `joblib`.
* Create repo structure: `src/`, `data/`, `models/`, `plots/`, `results/`.
* Write `README.md` introducing the project.

**Day 2:**

* Review Dijkstra algorithm & supervised learning basics.
* Run scikit-learn’s sample (Iris dataset).
* Write `src/network_builder.py` to generate a sample network graph.

---

## **Week 2 — Dijkstra & Candidate Paths**

**Day 3:**

* Write `src/path_generator.py` to generate top-K paths (`nx.all_simple_paths`).

**Day 4:**

* Add graph visualization (`nx.draw`), save `plots/network_example.png`.

---

## **Week 3 — Feature Engineering**

**Day 5:**

* Define 4 features: `sum_weight`, `avg_weight`, `path_len`, `max_weight`.

**Day 6:**

* Write `src/feature_extractor.py` with `extract_features(G, path)` function.
* Print test outputs.

---

## **Week 4 — Data Simulation**

**Day 7:**

* Write `src/simulator.py`: simulate attackers choosing random paths.

**Day 8:**

* Generate dataset (`simulate_dataset(n_samples=500)`) → `data/generated_paths.csv`.

**Day 9:**

* Check label distribution with `pandas`.

---

## **Week 5 — Train Machine Learning Model**

**Day 10:**

* Write `src/train_model.py`: train RandomForest, save `models/rf_model.pkl`.

**Day 11:**

* Add confusion matrix & feature importance → `results/train_report.txt`.

---

## **Week 6 — Pipeline Integration**

**Day 12:**

* Write `src/predict_path.py`: load model, predict most probable attack path.

**Day 13:**

* Write `main.py`: run full pipeline (simulate → train → predict).

---

## **Week 7 — Testing & Evaluation**

**Day 14:**

* Generate 3 different network scenarios.

**Day 15:**

* Compare results: ML model vs. Dijkstra-only.

**Day 16:**

* Plot accuracy and feature importance (Matplotlib).

---

## **Week 8 — Reporting & Submission**

**Day 17:**

* Write technical sections of `report.md`.

**Day 18:**

* Complete conclusion, finalize report, commit to GitHub.

**Day 19 (optional):**

* Prepare presentation slides.

---

# ✅ Pre-Submission Checklist

* [ ] `data/generated_paths.csv` ≥ 300 samples.
* [ ] `models/rf_model.pkl` exists.
* [ ] `main.py` runs end-to-end.
* [ ] `report.md` includes objectives, design, experiments, results, conclusions.
* [ ] Accuracy & feature importance charts included.
* [ ] Repo is public and includes clear `README.md`.

---

# 📚 Quick Learning Resources (20–30 mins/day)

* [NetworkX — Dijkstra](https://networkx.org/documentation/stable/reference/algorithms/shortest_paths.html)
* [Scikit-learn — Classification Quickstart](https://scikit-learn.org/stable/tutorial/basic/tutorial.html)
* [Pandas — DataFrame Basics](https://pandas.pydata.org/docs/user_guide/dsintro.html)

---

# 💡 Productivity Tips

* Commit after every session.
* Keep a small log: what you did, what went wrong.
* When busy: reduce `n_samples` in simulator.
* Focus on one file per session.

---
