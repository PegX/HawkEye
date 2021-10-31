import os
import tensorflow as tf
import readcfg
def load_data():
        catalog = "/home/secyoyo/Documents/angr/angr-dev/bingraphvis/bingraphvis/dataset/"
        y_target = []
        adj_matrix=[]
        eigenvector_matrix=[]
        for f in os.listdir(catalog):
            if ".cfg"  in f:
                data = readcfg.readcfg.load(catalog+f)

                y_target.append(data[0])
                adj_matrix.append(tf.cast(data[1].todense(),dtype=tf.float32))
                eigenvector_matrix.append(data[2])
        print('number of graphs %s or %s'%(len(eigenvector_matrix),len(y_target)))

        return adj_matrix,eigenvector_matrix,y_target


if __name__ == "__main__":
    adj_matrix,eigenvector_matrix,y_target = load_data()
    print(eigenvector_matrix[0][0])