import tensorflow as tf
import keras
import pickle
import pandas as pd
#
# from urlclass import Url

physical_devices = tf.config.list_physical_devices('GPU')
try:
    tf.config.experimental.set_memory_growth(physical_devices[0], True)
except:
  # Invalid device or cannot modify virtual devices once initialized.
    pass

# Load and initialise the RandomForest model
with open('/app/data/rfmodel.pickle', 'rb') as f:
    model = pickle.load(f)

# Load and initialize the CNN model
model_char = keras.models.load_model('/app/data/modelchar')

# Load and initialise the LiveSVM model
with open('/app/data/livesvm.pickle', 'rb') as f:
    livemodel = pickle.load(f)
    feature_list = ["link", "loc", "ext", "static", "uniq"]

# Generate a dictionary with character mapping
def gen_char_dict():
    """
    Generates a character dictionary with integer mapping
    :return: Dictionary of characters mapped to an integer
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-;.!?:'\"/\|_@#$%^&*~`+-=<>()[]{}"
    char_dict = {}
    char_dict["null"] = 0
    for i, char in enumerate(alphabet):
        char_dict[char] = i + 1
    char_dict["UNK"] = len(alphabet) + 1
    return char_dict

# Create variable to store the created character mapping dictionary
char_dict = gen_char_dict()

def strip_proto(s):
    """
    Removes protocol text from URLs
    :param s: String to remove protocol
    :return: String with protocol removed
    """
    return s.replace("https://", "").replace("http://", "").replace("www.", "")

def get_encoding_proto(url, length):
    """
    Maps the URL to its respective character encoding integer
    :param url: String representation of the URL
    :param length: Max length of the URL
    :return: List of integers representing the characters of the URL
    """
    url = strip_proto(url)
    enc_list = []
    url_str = url if len(url) <= length else url[:length]

    for char in url_str:
        if char in char_dict.keys():
            enc_list.append(char_dict[char])
        else:
            enc_list.append(char_dict["UNK"])

    for null in range(0, length - len(url_str)):
        enc_list.append(0)

    return enc_list

def get_rfprediction(url):
    """
    Gets prediction from the random forest classifier
    :param url: Url object
    :return: 1 for phishing 0 for benign
    """
    res = model.predict(url.generate_df())
    return int(res[0])

def get_cnnprediction(url):
    """
    Gets prediction from the CNN Model
    :param url: Url object
    :return: Float percentage probability of phishing
    """
    char_X = tf.constant([get_encoding_proto(url.url_str, 200)])
    return float(model_char(char_X)[0][1])*100

def get_livelinkprediction(url_phish):
    """
    Gets prediction from the CNN Model
    :param url: LiveUrl object
    :return: List with index 0 as the prediction and index 1 as the probability
    """
    if url_phish.dns is True and url_phish.access is True and url_phish.link_count > 0:
        data = {"link": url_phish.link_count, "loc": float(url_phish.get_linkperc("loc").split("%")[0])/100,
         "ext": float(url_phish.get_linkperc("ext").split("%")[0])/100, "static": float(url_phish.get_linkperc("static").split("%")[0])/100,
         "uniq": url_phish.get_uniqlocal()}
    elif url_phish.link_count == 0:
        data = {"link": 0, "loc": 0, "ext": 0, "static": 0, "uniq": 0}
    else:
        return
    url_frame = pd.DataFrame(data, index=[0])
    url_frame[feature_list] = livemodel['scaler'].transform(url_frame[feature_list])
    # result = int(livemodel['model'].predict([url_frame.iloc[0]])[0])
    proba = "{:.2f}".format(float(livemodel['model'].predict_proba([url_frame.iloc[0]])[0][1])*100)

    return proba
