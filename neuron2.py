import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split

import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from IPython import display


import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np


class Nett(nn.Module):
    def __init__(self):
        super().__init__()
        self.input = nn.Linear(in_features=69, out_features=16)
        self.hidden_1 = nn.Linear(in_features=16, out_features=16)
        self.output = nn.Linear(in_features=16, out_features=3)

    def forward(self, x):
        x = F.relu(self.input(x))
        x = F.relu(self.hidden_1(x))
        return self.output(x)




def neuronka(csv_file):
    # load the dataset, split into input (X) and output (y) variables
    dataset = np.loadtxt(csv_file, delimiter=',', skiprows=1)
    X = dataset[:, 0:69]
    y = dataset[:, 69]

    X = torch.tensor(X, dtype=torch.float32) #max 32b cisla
    y = torch.tensor(y, dtype=torch.long) #.reshape(-1, 1))

    print(X.shape,y.shape)

    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.8, random_state=42)

    train_data = TensorDataset(X_train, y_train)
    test_data = TensorDataset(X_test, y_test)

    train_loader = DataLoader(train_data, shuffle=True, batch_size=12)
    test_loader = DataLoader(test_data, batch_size=len(test_data.tensors[0]))

    model = Nett()
    print(model)

    print("Training data batches:")
    for X, y in train_loader:
        print(X.shape, y.shape)

    print("\nTest data batches:")
    for X, y in test_loader:
        print(X.shape, y.shape)

    num_epochs = 100
    train_accuracies, test_accuracies = [], []

    loss_function = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(params=model.parameters(), lr=0.01)

    for epoch in range(num_epochs):
        print(epoch)
        # Train set
        for X, y in train_loader:
            preds = model(X)
            pred_labels = torch.argmax(preds, axis=1)
            loss = loss_function(preds, y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
        train_accuracies.append(
            100 * torch.mean((pred_labels == y).float()).item()
        )

        # Test set
        X, y = next(iter(test_loader))
        pred_labels = torch.argmax(model(X), axis=1)
        test_accuracies.append(
            100 * torch.mean((pred_labels == y).float()).item()
        )

    fig = plt.figure(tight_layout=True)
    gs = gridspec.GridSpec(nrows=2, ncols=1)

    ax = fig.add_subplot(gs[0, 0])
    ax.plot(train_accuracies)
    ax.set_xlabel("Epoch")
    ax.set_ylabel("Training accuracy")

    ax = fig.add_subplot(gs[1, 0])
    ax.plot(test_accuracies)
    ax.set_xlabel("Epoch")
    ax.set_ylabel("Test accuracy")

    fig.align_labels()
    plt.show()