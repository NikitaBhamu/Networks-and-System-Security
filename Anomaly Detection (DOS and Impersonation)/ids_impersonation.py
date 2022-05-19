import csv
from csv import reader
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from time import time
import statistics
import sys
from sklearn import metrics
from mlxtend.plotting import plot_confusion_matrix


#Storing the time of different message ids in the file
id_times = {}
filename = sys.argv[1]
read_obj_dos = open(filename, 'r')
csv_reader_dos  = reader(read_obj_dos)
for row in csv_reader_dos :
    if(row[1] in id_times.keys()):
        id_times[row[1]].append(row[0])
    else:
        id_times[row[1]] = [row[0]]

diff_times = {}
for k in id_times.keys():
    diff_times[k] = []
    for i in range(1,len(id_times[k])):
        diff_times[k].append(float(id_times[k][i])-float(id_times[k][i-1]))

mean_timediff = {}
for k in diff_times.keys():
    mean_timediff[k] = statistics.mean(diff_times[k])
    # print(str(k) + " : "+ str(mean_timediff[k]))

stddev_timediff = {}
for k in diff_times.keys():
    stddev_timediff[k] = statistics.pstdev(diff_times[k])
    # print(str(k) + " : "+ str(stddev_timediff[k]))

X = []
y = []
last_arrival = {}
msg_ids = {}
id = 0
read_obj_dosNew = open(filename, 'r')
csv_reader_dosNew  = reader(read_obj_dosNew)
for row in csv_reader_dosNew :
    if(row[1] in last_arrival.keys()):
        if(row[1] not in msg_ids):
            msg_ids[row[1]] = id
            id += 1
        interval = float(row[0])-float(last_arrival[row[1]])
        last_arrival[row[1]] = float(row[0])
        X.append((msg_ids[row[1]], int(row[2]), mean_timediff[row[1]], stddev_timediff[row[1]], interval))
    else:
        if(row[1] not in msg_ids):
            msg_ids[row[1]] = id
            id += 1
        interval = float(0)
        last_arrival[row[1]] = float(row[0])
        X.append((msg_ids[row[1]], int(row[2]), mean_timediff[row[1]], stddev_timediff[row[1]], interval))

    if(row[int(row[2])+3] == 'R'):
        y.append(1)
    else:
        y.append(0)


xtrain, xtest, ytrain, ytest = train_test_split(X, y, test_size = 0.20)

# clf=RandomForestClassifier(n_estimators=100)
# clf.fit(xtrain,ytrain)
# y_pred=clf.predict(xtest)
# print("Accuracy:",metrics.accuracy_score(ytest, y_pred))

classifier = LogisticRegression()
classifier.fit(xtrain, ytrain)
ypred = classifier.predict(xtest)
print("Accuracy : ", float(classifier.score(xtest, ytest)))
# print(classification_report(ytest, ypred))
#
conf_matrix = confusion_matrix(y_true=ytest, y_pred=ypred)
fig, ax = plot_confusion_matrix(conf_mat=conf_matrix, figsize=(6, 6), cmap=plt.cm.Greens)
plt.xlabel('Predictions', fontsize=18)
plt.ylabel('Actuals', fontsize=18)
plt.title('Confusion Matrix', fontsize=18)
plt.show()
