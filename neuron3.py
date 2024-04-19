import time
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import convert_pcap_to_csv

from keras import models, losses, metrics, optimizers
from tensorflow.keras.layers import Dense
from sklearn.metrics import accuracy_score

def vyhodnoceni(nas_csv):
    model = models.load_model("tfmodel1.h5")

    nonNormalX = pd.read_csv(nas_csv)
    X_test = (nonNormalX - nonNormalX.min()) / (nonNormalX.max() - nonNormalX.min())

    y_hat = model.predict(X_test)  # X_test
    y_hat = [0 if val < 0.5 else 1 for val in y_hat]
    if(y_hat.count(0) >= y_hat.count(1)):
        print('Provoz neprobehl pomoci VPN')
    else:
        print('Provoz probehl pres VPN')
    print(y_hat)
    print(str(y_hat.count(0)) + ", " +  str(y_hat.count(1)))

def neuronka(csv_file):
    nonNormalX = pd.read_csv(csv_file, nrows=1000000, usecols=[i for i in range(1,70)])
    X = (nonNormalX - nonNormalX.min()) / (nonNormalX.max() - nonNormalX.min())
    y = pd.read_csv(csv_file, nrows=1000000, usecols=["encrypted"])

    # y = [int(c) for c in daY] ? uvidime
    # print(y)
    thislist = y["encrypted"].tolist()
    new_values = [int(hodnota) for hodnota in thislist]
    y["encrypted"] = new_values



    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.8)
    #random state kvuli stejne mnozine dat <- ulozeni modelu
    print(X_train)

    model = models.Sequential()
    # model = models.load_model("tfmodel.h5")

    model.add(Dense(units=128, activation='relu', input_dim=69))
    model.add(Dense(units=256, activation='relu'))
    model.add(Dense(units=1, activation='sigmoid'))

    model.compile(loss=losses.BinaryCrossentropy(), optimizer=optimizers.SGD(), metrics=[metrics.BinaryAccuracy()])

    start = time.time()
    model.fit(X_train, y_train, epochs=200, batch_size=200)
    stop = time.time()

    print(model)
    print("Trenuje: " + str(stop-start) + " s")

    y_hat = model.predict(X_test)       #X_test
    y_hat = [0 if val < 0.5 else 1 for val in y_hat]
    print(accuracy_score(y_test, y_hat))

    models.save_model(model,"tfmodel1.h5")

