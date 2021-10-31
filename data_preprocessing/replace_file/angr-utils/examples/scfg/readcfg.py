import _pickle as pickle
import gzip
import os
import sys
import string,re



class readcfg:
    def save(object, filename, bin=1):
        """Saves a compressed object to disk
        """
        file = gzip.GzipFile(filename, 'wb')
        file.write(pickle.dumps(object, bin))
        file.close()


    def load(filename):
        """Loads a compressed object from disk
        """
        file = gzip.GzipFile(filename, 'rb')
        buffer = ""

        data = file.read()
        #print(data)
        #print(type(data))
        #if(data == ""):
        #    break
        buffer += str(data)
        #print(buffer)
        object = pickle.loads(data)
        file.close()
        return object

    '''
    if __name__ == "__main__":
        import sys
        import os.path

        class Object:
            x = 7
            y = "This is an object."

        filename = sys.argv[1]
        if os.path.isfile(filename):
            o = load(filename)
            print ("Loaded %s" % o)
        else:
            o = Object()
            save(o, filename)
            print ("Saved %s" % o)
    '''
    if __name__ == '__main__':
        mnemonic = set()
        path = './generated_benign/'

        for root,dirs,files in os.walk(path):
            for _files_ in files:
                try:
                    print(str(path+_files_))
                    out_file = open('results_mnemonic_winpe32.txt','a')
                    cfgdata = load(str(path+_files_))
                    #print(cfgdata[2][1:10])
                    for i in range(len(cfgdata[2])):
                        #print(cfgdata[2][1:10])
                        #print("=========================")
                        for ii in range(len(cfgdata[2][i])):
                            mnemonic.add(cfgdata[2][i][ii])
                            out_file.write(cfgdata[2][i][ii])
                            out_file.write(' ')
                            
                    out_file.close()
                except:
                    out_file.close()

        

        print(mnemonic)