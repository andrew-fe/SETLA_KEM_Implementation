from sage.all import *
from hashlib import sha512
from random import getrandbits

# Парметры криптосистемы (стр. 15, таб. 1)
n = 1024
m = 2048  # 2n
omega = 16
d = 15
B = 32768  # 2^{15}
q = 33550337  # 2^{25} - 2^{12} + 1
k = 131

# Кольцо R = Z_q[x]/(x^n + 1)
R = PolynomialRing(Zmod(q), 'x').quotient('x^{} + 1'.format(n), 'x')


# Генерация случайного полинома из R с коэффициентами из [-d, d]
def randomdpoly(d):
    result = n * [0]
    for j in range(n):
        result[j] = randrange(-d, d + 1)
    return R(result)


# Хэш-функция
def H(x):
    h = int(sha512(str(x).encode()).hexdigest(), 16)
    result = []
    sum = 0
    while True:
        new_element = h % 3 - 1         # коэффициенты полинома в диапазоне [-1, 1]
        result.append(new_element)
        sum += abs(new_element)
        if sum == omega:                # когда сумма модулей коэффициентов равна omega - выход
            break
        h /= 3
    return R(result)


def bits_modular_rounding(x, bits):
    x = vector(x, ZZ)
    t = x % (2 ** d)
    for i in range(len(t)):
        if t[i] > 2 ** (d - 1):
            t[i] -= 2 ** d
    return R(list((x - t) / (2 ** d)))


def E(m, K):
    return m ^ K


def D(m, K):
    return m ^ K


def Encode(K):
    return R(list(str(K)))


def Decode(K):
    t = vector(K)
    return int(''.join(str(i) for i in t))


def check_polynomial(x, B):
    for i in x:
        if B < i < -B + q:
            return false
    return true


# Генерация пары ключей
def SETLA_gen_key(a1, a2):
    s = randomdpoly(1)
    e1 = randomdpoly(1)
    e2 = randomdpoly(1)
    t1 = a1 * s + e1
    t2 = a2 * s + e2
    return [{'t1': t1, 't2': t2}, {'s': s, 'e1': e1, 'e2': e2}]


def SETLA_KEM_Signcrypt(a1, a2, pkb, ska, pka, m):
    K = getrandbits(256)
    print(Encode(K))
    while True:
        y = randomdpoly(B)
        c = H((bits_modular_rounding(a1 * y, d), bits_modular_rounding(a2 * y, d), m, K, pka, pkb))
        z = ska['s'] * c + y            # s_a * c + y
        w1 = a1 * y - ska['e1'] * c     # a_1 * y - e_{a, 1} * c
        w2 = a2 * y - ska['e2'] * c     # a_2 * y - e_{a, 2} * c
        if check_polynomial(z, B - omega)\
                and bits_modular_rounding(a1 * y, d) == bits_modular_rounding(w1, d)\
                and bits_modular_rounding(a2 * y, d) == bits_modular_rounding(w2, d):
            break
    y0 = randomdpoly(B)
    x = pkb['t1'] * y + y0 + Encode(K)  # t_{b, 1} * y + y' + Encode(K)
    eps = E(m, k)
    return {'z': z, 'c': c, 'x': x, 'eps': eps}


def SETLA_KEM_Unsigncrypt(a1, a2, skb, pkb, pka, C):
    w1 = a1 * C['z'] - pka['t1'] * C['c']  # a_1 * z - t_{a, 1} * c
    w2 = a2 * C['z'] - pka['t2'] * C['c']  # a_2 * z - t_{a, 2} * c
    K = C['x'] - w1 * skb['s']
    print(K)
    # m = D(C['eps'], Decode(K))
    return 0


message = 12345

a1 = R.random_element()
a2 = R.random_element()

pka, ska = SETLA_gen_key(a1, a2)
pkb, skb = SETLA_gen_key(a1, a2)

C = SETLA_KEM_Signcrypt(a1, a2, pkb, ska, pka, message)
print(SETLA_KEM_Unsigncrypt(a1, a2, skb, pkb, pka, C))
