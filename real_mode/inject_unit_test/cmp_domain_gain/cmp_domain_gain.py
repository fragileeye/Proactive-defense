import cvxpy as cp
import numpy as np

class InjectSimulator:
    # Total segments 
    TOTAL_G = 9258*(10**2)
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

    def nothing(self):
        # internal gain
        Dlist = (self.Glist - self.Nlist * 2) * np.log(1 + 1/self.Nlist)
        print('Di: {0}\nmin Di: {1}'.format(Dlist, min(Dlist)))
        with open('nothing.txt', 'w') as fp:
            for value in Dlist:
                fp.write('{0}\n'.format(value))

    def average(self):
        # internal gain
        Dlist = (self.Glist - self.Nlist * 2) * np.log(1 + 1/self.Nlist)
        # print(Dlist)
        Clist = np.array([self.TOTAL_C/self.TOTAL_M] * self.TOTAL_M)
        # print(Clist)

        Ji_values = Clist * np.log(1 + self.Nlist) + Dlist
        print('Ji: {0}\nmin Ji: {1}'.format(Ji_values, min(Ji_values)))

        J_values = np.sum(Ji_values)
        print('Jv: {0}\navg Jv: {1}'.format(J_values, J_values/self.TOTAL_M))

        with open('average.txt', 'w') as fp:
            for value in Ji_values:
                fp.write('{0}\n'.format(value))

    def optim(self, alpha):
        # internal gain
        Dlist = (self.Glist - self.Nlist * 2) * np.log(1 + 1/self.Nlist)
        
        # to be solved
        Clist = cp.Variable(self.TOTAL_M, integer=True)

        # Minimum Ji: Objective function 1
        Ji = cp.min(cp.multiply(np.log(1 + self.Nlist), Clist) + Dlist)
        
        # Maximize Minimum Ji
        objective = cp.Maximize(Ji)

        constraints = [
            cp.sum(Clist) <= self.TOTAL_C,
            Clist >= 1]

        problem = cp.Problem(objective, constraints)

        optimal_value = problem.solve()

        epsilon = alpha * optimal_value

        # Maximum Jv: Objective function 2
        Clist = cp.Variable(self.TOTAL_M, integer=True)

        Ji = cp.min(cp.multiply(np.log(1 + self.Nlist), Clist) + Dlist)
        J = cp.sum(cp.multiply(np.log(1 + self.Nlist), Clist) + Dlist)

        objective = cp.Maximize(J)

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

        Jv_values = np.sum(Ji_values)
        print('Jv: {0}\navg Jv: {1}'.format(Jv_values, Jv_values/self.TOTAL_M))

        with open('optimal_{}.txt'.format(alpha), 'w') as fp:
            for value in Ji_values:
                fp.write('{0}\n'.format(value))

        
def main():
    simu = InjectSimulator()
    for alpha in [0.8, 0.85, 0.9, 0.95]:
        simu.optim(alpha)
    # simu.optim()
    simu.average()
    simu.nothing()

if __name__ == '__main__':
    main()




