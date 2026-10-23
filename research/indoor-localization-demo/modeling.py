"""Reusable, testable model helpers for the indoor-localization prototype."""

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier


def synthetic_data(seed: int = 42, n_per_room: int = 250) -> tuple[pd.DataFrame, pd.Series]:
    """Generate clearly synthetic RSSI-style features for four example rooms."""
    if n_per_room < 2:
        raise ValueError("n_per_room must be at least 2")
    rng = np.random.default_rng(seed)
    centers = [
        [-38, -62, -75, -80, -68, -84, -72],
        [-72, -40, -63, -77, -82, -69, -78],
        [-80, -70, -42, -61, -76, -83, -66],
        [-67, -81, -74, -43, -59, -72, -85],
    ]
    feature_rows = []
    labels = []
    for room_number, center in enumerate(centers, start=1):
        feature_rows.append(np.clip(rng.normal(center, 7, size=(n_per_room, 7)), -100, -25))
        labels.extend([f"Room {room_number}"] * n_per_room)
    features = pd.DataFrame(np.vstack(feature_rows), columns=[f"WiFi_{i}" for i in range(1, 8)])
    return features, pd.Series(labels, name="Location")


def make_classifier(max_depth: int = 6, seed: int = 42) -> Pipeline:
    """Build the Decision Tree pipeline used by the Streamlit demo."""
    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("tree", DecisionTreeClassifier(max_depth=max_depth, min_samples_leaf=2, random_state=seed)),
    ])
