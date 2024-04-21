import pandas as pd
from sklearn.model_selection import train_test_split

from keras import models, losses, metrics, optimizers
from tensorflow.keras.layers import Dense


def predicts(our_csv, our_model):
    """
    Performs prediction based on a trained neural network model.

    Args:
        our_csv (str): Path to the CSV file containing the data for predictions.
        our_model (str): Path to the file where the trained neural network model is stored.

    Returns:
        list: A list of predicted values (0 or 1) based on the input data.
    """
    model = models.load_model(our_model)

    x = pd.read_csv(our_csv)
    X_ev = (x - x.min()) / (x.max() - x.min())

    y_predicted = model.predict(X_ev)
    y_predicted = [0 if val < 0.5 else 1 for val in y_predicted]

    print(str("Pocet nul: " + str(y_predicted.count(0)) + " , pocet jednicek: " + str(y_predicted.count(1))))
    return y_predicted

def trainTestEvaluate(csv_file):
    """
    Trains and evaluates the performance of a neural network model.

    Args:
        csv_file (str): Path to the CSV file containing the training data.

    Returns:
        None
    """
    x = pd.read_csv(csv_file, nrows=1000000, usecols=[i for i in range(1,70)])
    X = (x - x.min()) / (x.max() - x.min())
    y = pd.read_csv(csv_file, nrows=1000000, usecols=["encrypted"])

    thislist = y["encrypted"].tolist()
    new_values = [int(val) for val in thislist]
    y["encrypted"] = new_values

    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.8)

    model = models.Sequential()

    model.add(Dense(units=128, activation='relu', input_dim=69))
    model.add(Dense(units=256, activation='relu'))
    model.add(Dense(units=1, activation='sigmoid'))

    model.compile(loss=losses.BinaryCrossentropy(), optimizer=optimizers.Adam(), metrics=[metrics.Accuracy()])

    model.fit(X_train, y_train, epochs=500, batch_size=50)
    results = model.evaluate(X_test, y_test, batch_size=50)

    print('{:.4%} presnost natrenovaneho modelu.'.format(results[1]))

    print('{:.13%} ztratovost natrenovaneho modelu.'.format(results[0]))

    models.save_model(model,"tfmodel2.h5")
