import streamlit as st
import pandas as pd
import joblib
from extract_features import extract_features 
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

def load_model():
    return joblib.load('DecisionTreeClassifier_model.pkl')

def classify_url(url, model):
    df = pd.DataFrame({'url': [url]})
    features = extract_features(df).iloc[:, 1:]  # Drop the original URL column
    features = features.drop('domain', axis=1)
    prediction = model.predict(features)
    prediction_map = {0: "Legitimate", 1: "Defacement", 2: "Phishing", 3: "Malware"}
    return prediction_map.get(prediction[0], "Unknown")

# Streamlit App
st.title("URL Legitimacy Classifier")
st.write("Enter a URL to classify its legitimacy:")

# Input field for URL
url_input = st.text_input("URL", "")

# Button to classify
if st.button("Classify"):
    if url_input:
        with st.spinner("Analyzing the URL..."):
            model = load_model()
            result = classify_url(url_input, model)
            st.success(f"The URL is classified as: {result}")

        # Add animation graphics
        if result == "Legitimate":
            st.balloons()
        else:
            st.error("Warning: Suspicious URL detected!")
    else:
        st.error("Please enter a valid URL.")

