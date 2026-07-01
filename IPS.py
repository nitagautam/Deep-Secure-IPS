# ---------- LOAD TRAINED MODELS ----------
import joblib

binary_model = joblib.load("models/binary_model.pkl")
multi_model = joblib.load("models/multi_model.pkl")


# ---------- PREDICTION FUNCTION FOR IPS ----------
def predict_packet(features_df):
    binary_pred = binary_model.predict(features_df)[0]
    binary_prob = binary_model.predict_proba(features_df)[0][1]

    # If normal traffic, return immediately
    if binary_pred == 0:
        return {
            "type": "Normal",
            "confidence": float(binary_prob)
        }

    # Multi-class classification (Attack type)
    multi_pred = multi_model.predict(features_df)[0]
    multi_prob = max(multi_model.predict_proba(features_df)[0])

    return {
        "type": multi_pred,
        "confidence": float(multi_prob)
    }
