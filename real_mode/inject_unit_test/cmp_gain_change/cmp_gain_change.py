import cvxpy as cp
import numpy as np

class InjectSimulatorV2:
    # Total segments 
    TOTAL_G = 9258*(10**4)
    # Total storage domains
    TOTAL_M = 18
    # Total sessions 
    TOTAL_N = 9258
    # Total injection, dynamic
    TOTAL_C = 345*100

    def __init__(self):
        self.Nlist = np.array([3775, 3410, 563 ,551, 457, 300,
            54, 51, 42, 19, 14, 13,
            3, 2, 1, 1, 1, 1]) 
        self.Glist = self.Nlist * (10**2)
        self.non_list = []
        self.avg_list = []
        self.avg_ext_list = []
        self.opt_list = []
        self.opt_ext_list = []

    def adjust(self, scaler):
        self.Glist = self.Nlist * scaler

    def stat(self):
        with open('nothing_change.txt', 'w') as fp:
            for value in self.non_list:
                fp.write('{0}\n'.format(value))
        with open('average_change.txt', 'w') as fp:
            for value in self.avg_list:
                fp.write('{0}\n'.format(value))
            fp.write('================================\n')
            for value in self.avg_ext_list:
                fp.write('{0}\n'.format(value))
        with open('optimal_change.txt', 'w') as fp:
            for value in self.opt_list:
                fp.write('{0}\n'.format(value))
            fp.write('================================\n')
            for value in self.opt_ext_list:
                fp.write('{0}\n'.format(value))


    def nothing(self):
        Dlist = (self.Glist - self.Nlist * 2) * np.log(1 + 1/self.Nlist)
        print('Di: {0}\nmin Di: {1}'.format(Dlist, min(Dlist)))
        self.non_list.append(min(Dlist))

    def average(self):
        Dlist = (self.Glist - self.Nlist * 2) * np.log(1 + 1/self.Nlist)
        # print(Dlist)
        Clist = np.array([self.TOTAL_C/self.TOTAL_M] * self.TOTAL_M)
        # print(Clist)

        Ji_values = Clist * np.log(1 + self.Nlist) + Dlist
        print('Ji: {0}\nmin Ji: {1}'.format(Ji_values, min(Ji_values)))

        Jv_values = Clist * np.log(1 + self.Nlist)
        print('Jv: {0}\navg Jv: {1}'.format(Jv_values, sum(Jv_values)/self.TOTAL_M))

        self.avg_list.append(min(Ji_values))
        self.avg_ext_list.append(sum(Jv_values)/self.TOTAL_M)

    def optim(self):
        Dlist = (self.Glist - self.Nlist * 2) * np.log(1 + 1/self.Nlist)
        # print(Dlist)
        
        Clist = cp.Variable(self.TOTAL_M, integer=True)

        # Minimum Ji, problem 1
        Ji = cp.min(cp.multiply(np.log(1 + self.Nlist), Clist) + Dlist)
        
        objective = cp.Maximize(Ji)

        constraints = [
            cp.sum(Clist) <= self.TOTAL_C,
            Clist >= 1]

        problem = cp.Problem(objective, constraints)

        optimal_value = problem.solve()

        epsilon = 0.95 * optimal_value

        # Maximum J, problem 2
        Clist = cp.Variable(self.TOTAL_M, integer=True)

        Ji = cp.min(cp.multiply(np.log(1 + self.Nlist), Clist) + Dlist)
        Jv = cp.sum(cp.multiply(np.log(1 + self.Nlist), Clist))

        objective = cp.Maximize(Jv)

        constraints = [
            Ji >= epsilon,
            cp.sum(Clist) <= self.TOTAL_C,
            Clist >= 1]

        problem = cp.Problem(objective, constraints)

        optimal_value = problem.solve()
        
        # checkout if the optimal status
        # print(problem.status)
        # print('optimal value: {0}'.format(optimal_value))
        print('optimal variables : {0}'.format(Clist.value))

        Ji_values = Clist.value * np.log(1 + self.Nlist) + Dlist
        print('Ji: {0}\nmin Ji: {1}'.format(Ji_values, min(Ji_values)))

        Jv_values = Clist.value * np.log(1 + self.Nlist)
        print('Jv: {0}\navg Jv: {1}'.format(Jv_values, sum(Jv_values)/self.TOTAL_M))
        
        self.opt_list.append(min(Ji_values))
        self.opt_ext_list.append(sum(Jv_values)/self.TOTAL_M)
        
def main():
    simu = InjectSimulatorV2()
    for scaler in range(100, 10100, 500):
        simu.adjust(scaler)
        simu.optim()
        simu.average()
        simu.nothing()
    simu.stat()

if __name__ == '__main__':
    main()
