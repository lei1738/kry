import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np


# define the model
class PimaClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.hidden1 = nn.Linear(64, 12)
        self.act1 = nn.ReLU()
        self.hidden2 = nn.Linear(12, 64)
        self.act2 = nn.ReLU()
        self.output = nn.Linear(64, 1)
        self.act_output = nn.Sigmoid()

    def forward(self, x):
        x = self.act1(self.hidden1(x))
        x = self.act2(self.hidden2(x))
        x = self.act_output(self.output(x))
        return x


def neuronka(csv_file):
    # load the dataset, split into input (X) and output (y) variables
    dataset = np.loadtxt(csv_file, delimiter=',')
    X = dataset[:, 0:64]
    y = dataset[:, 64]

    X = torch.tensor(X, dtype=torch.float32) #max 32b cisla
    y = torch.tensor(y, dtype=torch.float32).reshape(-1, 1)

    model = PimaClassifier()
    print(model)

    # train the model
    loss_fn = nn.BCELoss()  # binary cross entropy
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    n_epochs = 100
    batch_size = 10

    for epoch in range(n_epochs):
        for i in range(0, len(X), batch_size):
            Xbatch = X[i:i + batch_size]
            y_pred = model(Xbatch)
            ybatch = y[i:i + batch_size]
            loss = loss_fn(y_pred, ybatch)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

    # compute accuracy
    y_pred = model(X)
    accuracy = (y_pred.round() == y).float().mean()
    print(f"Accuracy {accuracy}")

    # make class predictions with the model

    predictions = (model(X) > 0.5).int()
    for i in range(5):
        print('%s => %d (expected %d)' % (X[i].tolist(), predictions[i], y[i]))
