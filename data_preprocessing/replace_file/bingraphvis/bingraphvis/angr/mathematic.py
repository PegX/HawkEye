import os
import numpy as np
import string

if __name__ == "__main__":
    dict={'mov':[0.1,0.000129312],'call':[2,3]}
    CALL = 'call'
    a = np.array(dict['mov'])
    b=np.array(dict['call'])
    print(a+b)
    print(type(a))