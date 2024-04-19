import time
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from keras import models, losses, metrics, optimizers
from tensorflow.keras.layers import Dense
from sklearn.metrics import accuracy_score

def neuronka(csv_file):
    X = pd.read_csv(csv_file, nrows=200, usecols=[i for i in range(64)])
    y = pd.read_csv(csv_file, nrows=200, usecols=["encrypted"])

    # y = [int(c) for c in daY] ? uvidime
    # print(y)
    # thislist = y["encrypted"].tolist()
    # new_values = [int(hodnota) for hodnota in thislist]
    # y["encrypted"] = new_values



    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.8,random_state=42)
    #random state kvuli stejne mnozine dat <- ulozeni modelu
    print(X_train)

    model = models.Sequential()
    # model = models.load_model("tfmodel.h5")

    model.add(Dense(units=32, activation='relu', input_dim=64))
    model.add(Dense(units=64, activation='relu'))
    model.add(Dense(units=1, activation='sigmoid'))

    model.compile(loss=losses.MeanAbsoluteError(), optimizer=optimizers.SGD(), metrics=[metrics.Accuracy()])

    start = time.time()
    model.fit(X_train, y_train, epochs=10, batch_size=50)
    stop = time.time()

    print(model)
    print("Trenuje: " + str(stop-start) + " s")

    y_hat = model.predict(X_test)
    y_hat = [0 if val < 0.5 else 1 for val in y_hat]
    print(accuracy_score(y_test, y_hat))

    print(y_hat)


    # models.save_model(model,"tfmodel.h5")

