import numpy as np
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix,
    classification_report, mean_absolute_error, mean_squared_error, r2_score,
)

from modeling import make_classifier, synthetic_data

st.set_page_config(page_title="Wireless Target Discovery", page_icon="📡", layout="wide")
URL = "https://archive.ics.uci.edu/dataset/422/wireless+indoor+localization"
st.title("Indoor Localization Research Demo")
st.caption("A separate, experimental ML prototype for exploring Wi-Fi RSSI-based room classification.")

st.info(
    "Dataset scope: the selected UCI Wireless Indoor Localization dataset has seven Wi-Fi "
    "signal-strength features and four room/location classes. It does not contain target-present/absent, "
    "distance, or search-time labels. This app predicts a room from dataset-shaped RSSI inputs and ranks "
    "candidate rooms; regression estimates an RSSI feature. It does not perform a live AetherLens scan."
)
with st.expander("Project workflow", expanded=False):
    st.write(
        "Signal measurements → data validation → Decision Tree room classification → rank candidate rooms "
        "→ display evaluation metrics. A Linear Regression module demonstrates continuous RSSI estimation."
    )

@st.cache_data(show_spinner=False)
def load_uci():
    from ucimlrepo import fetch_ucirepo
    ds = fetch_ucirepo(id=422)
    X = ds.data.features.copy()
    y = ds.data.targets.copy()
    if isinstance(y, pd.DataFrame):
        y = y.iloc[:, 0]
    X = X.apply(pd.to_numeric, errors="coerce")
    X.columns = [str(c).strip().replace(" ", "_") for c in X.columns]
    y = y.astype(str).str.strip()
    return X.reset_index(drop=True), y.reset_index(drop=True)

with st.sidebar:
    st.header("Model settings")
    source = st.radio("Dataset", ["Try UCI dataset", "Synthetic demo data"])
    test_pct = st.slider("Test set (%)", 10, 40, 25, 5)
    depth = st.slider("Decision Tree max depth", 2, 15, 6)
    seed = st.number_input("Random seed", 0, 9999, 42)
    st.markdown(f"[UCI dataset page]({URL})")

data_label = "UCI Wireless Indoor Localization"
try:
    if source == "Synthetic demo data":
        X, y = synthetic_data(seed=int(seed))
        data_label = "Synthetic data (not real measurements)"
    else:
        X, y = load_uci()
except Exception as exc:
    st.warning(
        f"Could not load the UCI dataset ({type(exc).__name__}). Using clearly labelled synthetic data; "
        "do not report these metrics as real-world results."
    )
    X, y = synthetic_data(seed=int(seed))
    data_label = "Synthetic fallback (not real measurements)"

X = X.apply(pd.to_numeric, errors="coerce")
valid = X.notna().any(axis=1) & y.notna()
X, y = X.loc[valid].reset_index(drop=True), y.loc[valid].astype(str).reset_index(drop=True)
if len(X) < 8 or y.nunique() < 2:
    st.error("Need at least eight usable records and two location classes.")
    st.stop()

try:
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=test_pct / 100, random_state=int(seed), stratify=y
    )
except ValueError as exc:
    st.error(f"Unable to create a stratified train/test split: {exc}")
    st.stop()

clf = make_classifier(max_depth=int(depth), seed=int(seed))
clf.fit(Xtr, ytr)
pred = clf.predict(Xte)
classes = clf.named_steps["tree"].classes_
acc = accuracy_score(yte, pred)
prec = precision_score(yte, pred, average="macro", zero_division=0)
rec = recall_score(yte, pred, average="macro", zero_division=0)
f1 = f1_score(yte, pred, average="macro", zero_division=0)
st.caption(
    f"**Source:** {data_label} · **Rows:** {len(X)} · "
    f"**Features:** {X.shape[1]} · **Classes:** {y.nunique()}"
)

t1, t2, t3, t4, t5 = st.tabs(
    ["Room estimate", "Evaluation", "RSSI regression", "Dataset", "Prototype checks"]
)

with t1:
    st.subheader("Predict and prioritise candidate rooms")
    st.write("Set signal strengths (RSSI, dBm) in the same feature order as the chosen dataset.")
    med = X.median(numeric_only=True).to_dict()
    cols = st.columns(2)
    values = {}
    for i, col in enumerate(X.columns):
        lo = min(float(X[col].min()), -100.0)
        hi = max(float(X[col].max()), 0.0)
        if lo == hi:
            hi = lo + 1
        with cols[i % 2]:
            values[col] = st.slider(
                f"{col} (dBm)", float(lo), float(hi),
                float(np.clip(med[col], lo, hi)), 1.0, key=f"rss_{i}"
            )
    inp = pd.DataFrame([values], columns=X.columns)
    probs = clf.predict_proba(inp)[0]
    ranking = pd.DataFrame(
        {"Candidate location": classes, "Model score (%)": np.round(probs * 100, 2)}
    ).sort_values("Model score (%)", ascending=False).reset_index(drop=True)
    a, b = st.columns([1, 1.4])
    with a:
        st.metric("Most likely room", str(clf.predict(inp)[0]))
        st.metric("Top model score", f"{ranking.iloc[0]['Model score (%)']:.2f}%")
        st.dataframe(ranking, hide_index=True, use_container_width=True)
    with b:
        fig, ax = plt.subplots()
        ax.barh(ranking["Candidate location"][::-1], ranking["Model score (%)"][::-1])
        ax.set_xlabel("Model score (%)")
        ax.set_title("Candidate-room ranking")
        ax.set_xlim(0, 100)
        fig.tight_layout()
        st.pyplot(fig)
        plt.close(fig)
    st.warning(
        "Scores are model outputs, not calibrated probabilities or proof of a target's presence. "
        "The dataset labels rooms; it does not label target presence."
    )

with t2:
    st.subheader("Decision Tree classification evaluation")
    a, b, c, d = st.columns(4)
    a.metric("Accuracy", f"{acc:.3f}")
    b.metric("Precision (macro)", f"{prec:.3f}")
    c.metric("Recall (macro)", f"{rec:.3f}")
    d.metric("F1 (macro)", f"{f1:.3f}")
    cm = confusion_matrix(yte, pred, labels=classes)
    fig, ax = plt.subplots(figsize=(7, 5))
    im = ax.imshow(cm)
    ax.set_title("Confusion matrix")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_xticks(range(len(classes)), classes, rotation=35, ha="right")
    ax.set_yticks(range(len(classes)), classes)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center")
    fig.colorbar(im, ax=ax)
    fig.tight_layout()
    st.pyplot(fig)
    plt.close(fig)
    st.dataframe(
        pd.DataFrame(classification_report(yte, pred, output_dict=True, zero_division=0)).T.round(3),
        use_container_width=True,
    )
    importance = pd.DataFrame(
        {"Feature": X.columns, "Importance": clf.named_steps["tree"].feature_importances_}
    ).sort_values("Importance")
    fig, ax = plt.subplots()
    ax.barh(importance["Feature"], importance["Importance"])
    ax.set_title("Feature importance")
    fig.tight_layout()
    st.pyplot(fig)
    plt.close(fig)
    st.download_button(
        "Download test predictions CSV",
        pd.DataFrame(
            {"actual": yte.astype(str).to_numpy(), "predicted": pd.Series(pred).astype(str).to_numpy()}
        ).to_csv(index=False),
        "test_predictions.csv", "text/csv",
    )

with t3:
    st.subheader("Linear Regression: estimate an RSSI feature")
    st.write(
        "The dataset has room labels but no distance or search-time target. "
        "This supporting model predicts the first RSSI feature from the remaining features."
    )
    if X.shape[1] < 2:
        st.warning("At least two numeric features are required.")
    else:
        target = X.columns[0]
        feats = list(X.columns[1:])
        df = X[feats + [target]].dropna()
        if len(df) < 10:
            st.warning("Not enough complete rows for regression.")
        else:
            xr, xt, yr, yt = train_test_split(
                df[feats], df[target], test_size=test_pct / 100, random_state=int(seed)
            )
            reg = Pipeline([
                ("imputer", SimpleImputer(strategy="median")),
                ("linear", LinearRegression()),
            ])
            reg.fit(xr, yr)
            rp = reg.predict(xt)
            mae = mean_absolute_error(yt, rp)
            mse = mean_squared_error(yt, rp)
            rmse = float(np.sqrt(mse))
            r2 = r2_score(yt, rp)
            a, b, c, d = st.columns(4)
            a.metric("MAE (dBm)", f"{mae:.2f}")
            b.metric("MSE", f"{mse:.2f}")
            c.metric("RMSE (dBm)", f"{rmse:.2f}")
            d.metric("R²", f"{r2:.3f}")
            fig, ax = plt.subplots()
            ax.scatter(yt, rp, alpha=0.6)
            lo = min(float(yt.min()), float(np.min(rp)))
            hi = max(float(yt.max()), float(np.max(rp)))
            ax.plot([lo, hi], [lo, hi], "--")
            ax.set_xlabel("Actual RSSI")
            ax.set_ylabel("Predicted RSSI")
            ax.set_title("Actual vs predicted signal strength")
            fig.tight_layout()
            st.pyplot(fig)
            plt.close(fig)
            st.dataframe(
                pd.DataFrame({"Actual RSSI": yt.to_numpy(), "Predicted RSSI": rp}).head(20).round(2),
                use_container_width=True,
            )
    st.warning("This is a regression demonstration, not a distance or search-time model.")

with t4:
    st.subheader("Dataset explorer")
    a, b, c = st.columns(3)
    a.metric("Rows", len(X))
    b.metric("Features", X.shape[1])
    c.metric("Classes", y.nunique())
    st.dataframe(X.assign(Location=y).head(30), use_container_width=True)
    st.write("Missing values")
    st.dataframe(X.isna().sum().rename("Missing count").to_frame())
    st.write("Class distribution")
    st.dataframe(y.value_counts().rename_axis("Location").reset_index(name="Count"), hide_index=True)
    st.download_button(
        "Download loaded dataset CSV", X.assign(Location=y).to_csv(index=False),
        "wireless_localization.csv", "text/csv",
    )

with t5:
    st.subheader("Basic prototype checks")
    checks = [
        ("Dataset has records", len(X) > 0, f"{len(X)} rows"),
        ("At least two classes", y.nunique() >= 2, f"{y.nunique()} classes"),
        ("Numeric features", all(pd.api.types.is_numeric_dtype(X[c]) for c in X.columns), "Feature columns checked"),
        ("Classifier trained", hasattr(clf.named_steps["tree"], "classes_"), "Decision Tree fitted"),
        ("Scores sum to one", abs(float(probs.sum()) - 1) < 1e-6, f"Sum = {probs.sum():.6f}"),
        ("Test predictions produced", len(yte) == len(pred), f"{len(pred)} predictions"),
    ]
    st.dataframe(pd.DataFrame([
        {"Check": name, "Status": "PASS" if ok else "FAIL", "Details": detail}
        for name, ok, detail in checks
    ]), hide_index=True, use_container_width=True)
    if all(ok for _, ok, _ in checks):
        st.success("All built-in demonstration checks passed.")
    else:
        st.error("Some checks failed. Review the dataset and model settings.")

st.divider()
st.caption(
    "Research prototype only. Performance depends on the selected data and split. "
    "Do not use as a safety-critical tracking or security system."
)
