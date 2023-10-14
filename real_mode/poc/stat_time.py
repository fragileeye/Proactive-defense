from multiprocessing import Process 
from scapy.all import *
import os 
import sys 

def stat_time(rpath):
    dir_path, fname = os.path.split(rpath)
    stat_path = os.path.join(dir_path, 'time.txt')
    try:
        start_time = end_time = 0
        reader = PcapReader(rpath)
        for pkt in reader:
            if not start_time:
                start_time = pkt.time 
            end_time = pkt.time 
        with open(stat_path, 'a+') as fp:
            fp.write('[{0}] start time: {1} end time: {2}'.format(
                fname, start_time, end_time
            ))
    except Exception as e:
        print(e)
        
        
def main():
    for i, opt in enumerate(sys.argv):
        if opt == '-r':
            dir_path = sys.argv[i+1]
    if not os.path.exists(dir_path):
        print('{0} does not exist.'.format(dir_path))
        return 
    ps_list = []
    for fname in os.listdir(dir_path):
        if not fname.startswith('univ1_pt'):
            continue
        rpath = os.path.join(dir_path, fname)
        ps = Process(target=stat_time, args=(rpath,))
        ps.start()
        ps_list.append(ps)
    for ps in ps_list:
        ps.join()

if __name__ == '__main__':
    main()
    
