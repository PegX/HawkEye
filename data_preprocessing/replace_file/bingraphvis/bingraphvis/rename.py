import os

def rm_space():
    catalog = "./dataset_test34/"
    for f in os.listdir(catalog):
        n  = ''.join(f.split())
        n  =  n.replace('<', "")
        n  =  n.replace('>', "")
        n  =  n.replace(")", "")
        n  =  n.replace("(", "")


        os.rename(catalog+f, catalog+n)
           

if __name__=="__main__":
    rm_space()