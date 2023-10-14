import os 
import sys 
import numpy as np

def stat_cpu(dpath):
    for fname in os.listdir(dpath):
        if not fname.endswith('txt'):
            continue
        cpu_list = []
        fpath = os.path.join(dpath, fname)
        with open(fpath, 'r+') as fp:
            while True:
                line = fp.readline()
                if not line:
                    break
                cpu_list.append(float(line))
            Q3 = np.quantile(np.array(cpu_list), 0.75)
            filter_list = [v for v in cpu_list if v >= Q3]
            print(fname, sum(filter_list)/len(filter_list))

if __name__ == '__main__':
    stat_cpu(r'cpu')
            
                
