import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

from keras import models, losses, metrics, optimizers
from tensorflow.keras.layers import Dense

def evaluation(our_csv, our_model):
    model = models.load_model(our_model)
    #save our_csv - 2

    #hash our_csv - 1
    non_normalX = pd.read_csv(our_csv)
    X_ev = (non_normalX - non_normalX.min()) / (non_normalX.max() - non_normalX.min())

    y_predicted = model.predict(X_ev)
    y_predicted = [0 if val < 0.5 else 1 for val in y_predicted]
    if y_predicted.count(0) >= y_predicted.count(1):
        print('Sitovy provoz neprobehl pres VPN.')
    else:
        print('Sitovy provoz probehl pres VPN.')
    print(y_predicted)
    #add new column to our_csv - 2

    print(str(y_predicted.count(0)) + "- 0, " +  str(y_predicted.count(1)) + " - 1")

def trainTest(csv_file):
    non_normalX = pd.read_csv(csv_file, nrows=1000000, usecols=[i for i in range(1,70)])
    X = (non_normalX - non_normalX.min()) / (non_normalX.max() - non_normalX.min())
    y = pd.read_csv(csv_file, nrows=1000000, usecols=["encrypted"])

    thislist = y["encrypted"].tolist()
    new_values = [int(val) for val in thislist]
    y["encrypted"] = new_values

    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.8)

    model = models.Sequential()

    model.add(Dense(units=128, activation='relu', input_dim=69))
    model.add(Dense(units=256, activation='relu'))
    model.add(Dense(units=1, activation='sigmoid'))

    model.compile(loss=losses.BinaryCrossentropy(), optimizer=optimizers.SGD(), metrics=[metrics.BinaryAccuracy()])

    model.fit(X_train, y_train, epochs=200, batch_size=200)


    y_predicted = model.predict(X_test)

    y_predicted = [0 if val < 0.5 else 1 for val in y_predicted]
    print('{:.1%} procentni uspesnost natrenovaneho modelu.'.format(accuracy_score(y_test, y_predicted))) #return?

    models.save_model(model,"tfmodel.h5")

