import _pickle as pickle
import gzip

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