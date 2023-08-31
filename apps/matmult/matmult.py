import numpy as np

rows = 4
cols = 4

A = np.matrix([[i+2*j for j in range(cols)] for i in range(rows)])

print("A =\n%s" % A)

b = np.array([1 if i == 0 else 0 for i in range(cols)])

print("A[i][j]=%s" % A[0,0])

print("Ab =%s" % A.dot(b))

dA = dict()
for d in range(cols):
    dA[d] = [A[i,(i+d) % cols] for i in range(cols)]

print("dA =%s" % dA)


res = np.array([0 for _ in range(cols)])
for d in dA:
    br = np.roll(b, d)
    res += d*br

print("res =%s" % res)