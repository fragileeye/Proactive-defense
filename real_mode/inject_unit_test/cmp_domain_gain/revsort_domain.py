import os 
import re 
import sys 

def rev_sort(rpath, wpath):
    pattern = re.compile(r'([^ ]+)\s+sessions:\s+(\d+),\s+segments:\s+(\d+)\s+')
    with open(rpath, 'r') as fp:
        data = fp.read()
    result = re.findall(pattern, data)
    result = sorted(result, key=lambda x:(int(x[1]), int(x[2])), reverse=True)
    with open(wpath, 'w') as fp:
        for x in result:
            fp.write('{0} {1} {2}\n'.format(x[0], x[1], x[2]))
    

def main():
    for i, opt in enumerate(sys.argv):
        if opt == '-r':
            rpath = sys.argv[i+1]
        elif opt == '-w':
            wpath = sys.argv[i+1]
    rev_sort(rpath, wpath)

if __name__ == '__main__':
    main()