import pandas as pd
import numpy as np
import os

from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ----------1. LOAD DATA---------------

train = pd.read_excel(r"C:\Users\Acer\Desktop\Smart IPS\UNSW_NB15_training-set.xlsx")
test = pd.read_excel(r"C:\Users\Acer\Desktop\Smart IPS\UNSW_NB15_testing-set.xlsx")

print("Datasets successfully loaded.")
print("Training Shape:", train.shape)
print("Testing Shape:", test.shape)

#------ 2. DEFINE FEATURES & TARGETS--------

# Binary target (0 = Normal, 1 = Attack)
y_binary_train = train["label"]
y_binary_test = test["label"]

# Multi-class target (attack category)
y_multi_train = train["attack_cat"]
y_multi_test = test["attack_cat"]

#Using selected features
selected_features = [
    "dur",
    "proto",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "sttl",
    "dttl",
    "rate",
    "sload",
    "dload",
    "sinpkt",
    "dinpkt"
]

X_train = train[selected_features]
X_test = test[selected_features]
print("Selected Features:")
print(X_train.columns.tolist())

#-------------- 3. PREPROCESSING PIPELINE--------------

# Identify categorical & numerical columns
categorical_cols = X_train.select_dtypes(include=["object"]).columns
numerical_cols = X_train.select_dtypes(include=["int64", "float64"]).columns

preprocessor = ColumnTransformer(
    transformers=[
        ("num", StandardScaler(), numerical_cols),
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols)
    ]
)
X_train_transformed = preprocessor.fit_transform(X_train)
print("Transformed Shape:", X_train_transformed.shape)

#------------- 4. BINARY MODEL PIPELINE-----------


binary_model = Pipeline(steps=[
    ("preprocessing", preprocessor),
    ("classifier", RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced"))
])

binary_model.fit(X_train, y_binary_train)

binary_pred = binary_model.predict(X_test)

print("\n===== BINARY MODEL REPORT =====")
print("Accuracy:", accuracy_score(y_binary_test, binary_pred))
print(classification_report(y_binary_test, binary_pred))


#--------- 5. MULTI-CLASS MODEL PIPELINE---------

multi_model = Pipeline(steps=[
    ("preprocessing", preprocessor),
    ("classifier", RandomForestClassifier(n_estimators=100, random_state=42))
])

multi_model.fit(X_train, y_multi_train)

multi_pred = multi_model.predict(X_test)

print("\n===== MULTI-CLASS MODEL REPORT =====")
print("Accuracy:", accuracy_score(y_multi_test, multi_pred))
print(classification_report(y_multi_test, multi_pred))



import joblib

# Save trained models
joblib.dump(binary_model, "binary_model.pkl")
joblib.dump(multi_model, "multi_model.pkl")




