import re
from urllib.parse import urlparse
from tld import get_tld


def extract_features(df):
    """
    Extracts various features from the 'url' column in the given DataFrame.
    Parameters:
        df (DataFrame): The input DataFrame with a 'url' column.    
    Returns:
        DataFrame: The DataFrame with additional feature columns.
    """
    
    # Feature 1: Length of the URL
    df['url_len'] = df['url'].apply(lambda x: len(str(x)))
    
    # Feature 2: Extract primary domain from URL
    def process_tld(url):
        try:
            res = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
            pri_domain = res.parsed_url.netloc
        except:
            pri_domain = None
        return pri_domain
    df['domain'] = df['url'].apply(lambda i: process_tld(i))
    
    # Feature 3: Count of special characters in the URL
    special_chars = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
    for char in special_chars:
        df[char] = df['url'].apply(lambda i: i.count(char))
    
    # Feature 4: Check if the URL is abnormal (contains hostname outside its domain)
    def abnormal_url(url):
        hostname = urlparse(url).hostname
        hostname = str(hostname)
        match = re.search(hostname, url)
        return 1 if match else 0
    df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))
    
    # Feature 5: Check if the URL uses HTTPS
    def httpSecure(url):
        scheme = urlparse(url).scheme
        return 1 if scheme == 'https' else 0
    df['https'] = df['url'].apply(lambda i: httpSecure(i))
    
    # Feature 6: Count the number of digits in the URL
    def digit_count(url):
        return sum(1 for i in url if i.isnumeric())
    df['digits'] = df['url'].apply(lambda i: digit_count(i))
    
    # Feature 7: Count the number of letters in the URL
    def letter_count(url):
        return sum(1 for i in url if i.isalpha())
    df['letters'] = df['url'].apply(lambda i: letter_count(i))
    
    # Feature 8: Check for URL shortening services
    def Shortining_Service(url):
        shortening_services = re.compile(
            'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
            'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
            'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
            'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
            'tr\.im|link\.zip\.net'
        )
        return 1 if shortening_services.search(url) else 0
    df['Shortining_Service'] = df['url'].apply(lambda x: Shortining_Service(x))
    
    # Feature 9: Check if the URL contains an IP address
    def having_ip_address(url):
        ip_address_pattern = re.compile(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
            r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)|'
            r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
            r'([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
            r'((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)'
        )
        return 1 if ip_address_pattern.search(url) else 0
    df['having_ip_address'] = df['url'].apply(lambda i: having_ip_address(i))
    
    return df
