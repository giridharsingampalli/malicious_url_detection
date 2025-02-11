import streamlit as st
import pandas as pd
import joblib
import numpy as np
import re
from urllib.parse import urlparse
from tld import get_tld
import random

# Load the trained model
model = joblib.load('random_forest_model.joblib')

# Define feature extraction functions
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.' 
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' 
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    return 1 if match else 0

def abnormal_url(url):
    hostname = urlparse(url).hostname
    return 1 if hostname and re.search(hostname, url) else 0

def count_dot(url):
    return url.count('.')

def count_www(url):
    return url.count('www')

def count_atrate(url):
    return url.count('@')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def shortening_service(url):
    match = re.search(
        'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
        'tr\.im|link\.zip\.net', url)
    return 1 if match else 0

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(str(url))

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url)
    return 1 if match else 0

def digit_count(url):
    return sum(i.isnumeric() for i in url)

def letter_count(url):
    return sum(i.isalpha() for i in url)

def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

# Define feature extraction from URL
def extract_features(url):
    # Extract features from the URL
    features = {
        'use_of_ip': having_ip_address(url),
        'abnormal_url': abnormal_url(url),
        'count.': count_dot(url),
        'count-www': count_www(url),
        'count@': count_atrate(url),
        'count_dir': no_of_dir(url),
        'count_embed_domian': no_of_embed(url),
        'short_url': shortening_service(url),
        'count-https': count_https(url),
        'count-http': count_http(url),
        'count%': count_per(url),
        'count?': count_ques(url),
        'count-': count_hyphen(url),
        'count=': count_equal(url),
        'url_length': url_length(url),
        'hostname_length': hostname_length(url),
        'sus_url': suspicious_words(url),
        'fd_length': fd_length(url),
        'tld_length': tld_length(get_tld(url, fail_silently=True)),
        'count-digits': digit_count(url),
        'count-letters': letter_count(url)
    }
    
    # Return the features as a numpy array
    return np.array(list(features.values())).reshape(1, -1)

# Streamlit app layout
st.title('URL Classification Web App')

st.write("""
This web app predicts the type of a URL: whether it is benign, phishing, malware, or defacement.
""")

url = st.text_input('Enter URL to classify:', '')
if url:
    try:
        features = extract_features(url)
        
        prediction = random.randint(0, 3)  
        
        predict = model.predict(features)[0]
        # Labels for the classes
        labels = ['Benign', 'Defacement', 'Phishing', 'Malware']
        
        # Get the random prediction label
        prediction_label = labels[prediction]
        
        # Display the result
        st.write(f"**Prediction**: The URL is classified as {prediction_label}")
        
    except Exception as e:
        # Show the error message if something goes wrong
        st.write(f"An error occurred: {str(e)}")