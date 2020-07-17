from sage.all import *
from hashlib import sha512
from random import getrandbits
from random import choice
from string import ascii_lowercase
from time import time
from pympler.asizeof import asizeof
from Crypto.Cipher import AES

# Параметры симметричной криптосистемы
SYMMETRIC_KEY_LEN = 256

# Размер тестовой выборки
TEST_CASE_SIZE = 100
TEST_MAX_MESSAGE_LEN = 1000000000

# Парметры криптосистемы (стр. 15, таб. 1)
n = 1024
m = 2048        # 2n
omega = 16
d = 15
B = 32768       # 2^{15}
q = 33550337    # 2^{25} - 2^{12} + 1
k = 131

# Кольцо R = Z_q[x]/(x^n + 1)
R = PolynomialRing(Zmod(q), 'x').quotient('x^{} + 1'.format(n), 'x')

# Открытые общеизвестные показатели
a1 = R.random_element()
a2 = R.random_element()


# Генерация случайного полинома из R с коэффициентами из [-d, d]
def random_poly(d):
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


def encrypt(m, k):
    return AES.new(k.to_bytes(SYMMETRIC_KEY_LEN // 8, byteorder='big'), AES.MODE_CFB, 16 * '\x00').encrypt(m)


def decrypt(c, k):
    try:
        return AES.new(k.to_bytes(SYMMETRIC_KEY_LEN // 8, byteorder='big'), AES.MODE_CFB, 16 * '\x00').decrypt(c).decode("utf-8")
    finally:
        return ''


def int_to_bits(x):
    return [int(digit) for digit in bin(x)[2:]]


def bits_to_int(x):
    return int("".join(str(x) for x in x), 2)


def encode(m):
    qq = floor((q - 1) / 2)
    m = int_to_bits(m)
    result = []
    for i in m:
        result.append(i * qq)
    return R(result)


def decode(m):
    m = vector(m)
    qq = ceil(q / 4)
    result = []
    for i in range(SYMMETRIC_KEY_LEN):
        if qq - 1 < m[i] < -qq + q:
            result.append(1)
        else:
            result.append(0)
    return bits_to_int(result)


def check_polynomial(x, B):
    if x not in R:
        return false
    for i in x:
        if B < i < -B + q:
            return false
    return true


# Генерация пары ключей
def SETLA_Key_generation(a1, a2):
    start_time = time()
    s = random_poly(1)
    e1 = random_poly(1)
    e2 = random_poly(1)
    t1 = a1 * s + e1
    t2 = a2 * s + e2
    end_time = time()
    return {'pk': {'t1': t1, 't2': t2}, 'sk': {'s': s, 'e1': e1, 'e2': e2}}, end_time - start_time


def SETLA_KEM_Signcrypt(a1, a2, pkb, ska, pka, m):
    start_time = time()
    K = getrandbits(SYMMETRIC_KEY_LEN)
    while True:
        y = random_poly(B)
        c = H((bits_modular_rounding(a1 * y, d), bits_modular_rounding(a2 * y, d), m, K, pka, pkb))
        z = ska['s'] * c + y            # s_a * c + y
        w1 = a1 * y - ska['e1'] * c     # a_1 * y - e_{a, 1} * c
        w2 = a2 * y - ska['e2'] * c     # a_2 * y - e_{a, 2} * c
        if check_polynomial(z, B - omega)\
                and bits_modular_rounding(a1 * y, d) == bits_modular_rounding(w1, d)\
                and bits_modular_rounding(a2 * y, d) == bits_modular_rounding(w2, d):
            break
    y0 = random_poly(B)
    x = pkb['t1'] * y + y0 + encode(K)  # t_{b, 1} * y + y' + Encode(K)
    eps = encrypt(m, K)
    end_time = time()
    return {'z': z, 'c': c, 'x': x, 'eps': eps}, end_time - start_time


def SETLA_KEM_Unsigncrypt(a1, a2, skb, pkb, pka, C):
    start_time = time()
    w1 = a1 * C['z'] - pka['t1'] * C['c']  # a_1 * z - t_{a, 1} * c
    w2 = a2 * C['z'] - pka['t2'] * C['c']  # a_2 * z - t_{a, 2} * c
    K = decode(C['x'] - w1 * skb['s'])
    m = decrypt(C['eps'], K)
    result = ''
    if C['c'] == H((bits_modular_rounding(w1, d), bits_modular_rounding(w2, d), m,  K, pka, pkb))\
            and check_polynomial(C['z'], B - omega):
        result = m
    end_time = time()
    return result, end_time - start_time


def test_key_generation():
    average_time = 0.0
    average_pk_size = 0
    average_sk_size = 0
    for i in range(TEST_CASE_SIZE):
        keys, current_time = SETLA_Key_generation(a1, a2)
        average_pk_size += asizeof(keys['pk'])
        average_sk_size += asizeof(keys['sk'])
        average_time += current_time
    print("Average key generation time, s:", average_time / TEST_CASE_SIZE)
    print("Average pk size, bytes:", average_pk_size / TEST_CASE_SIZE)
    print("Average sk size, bytes:", average_sk_size / TEST_CASE_SIZE)


def random_word(length):
    letters = ascii_lowercase
    return ''.join(choice(letters) for i in range(length))


def test_signcryption():
    keys_a, null = SETLA_Key_generation(a1, a2)
    keys_b, null = SETLA_Key_generation(a1, a2)
    for message_length in range(100, TEST_MAX_MESSAGE_LEN, 100):
        message = random_word(message_length)
        average_time = 0.0
        average_signcryptiontext_size = 0
        for i in range(TEST_CASE_SIZE):
            signcryptiontext, signcryption_time = SETLA_KEM_Signcrypt(a1, a2, keys_b['pk'], keys_a['sk'], keys_a['pk'], message)
            average_time += signcryption_time
            average_signcryptiontext_size += asizeof(signcryptiontext)
        print("Message length, symbols:", message_length)
        print("Average signcryption time, s:", average_time / TEST_CASE_SIZE)
        print("Average signcryptiontext size, bytes:", average_signcryptiontext_size / TEST_CASE_SIZE)


def test_unsigncryption():
    keys_a, null = SETLA_Key_generation(a1, a2)
    keys_b, null = SETLA_Key_generation(a1, a2)
    for message_length in range(100, TEST_MAX_MESSAGE_LEN, 100):
        message = random_word(message_length)
        average_time = 0.0
        for i in range(TEST_CASE_SIZE):
            signcryptiontext, signcryption_time = SETLA_KEM_Signcrypt(a1, a2, keys_b['pk'], keys_a['sk'], keys_a['pk'], message)
            null, unsigncryption_time = SETLA_KEM_Unsigncrypt(a1, a2, keys_b['sk'], keys_b['pk'], keys_a['pk'], signcryptiontext)
            average_time += unsigncryption_time
        print("Message length, symbols:", message_length)
        print("Average signcryption time, s:", average_time / TEST_CASE_SIZE)


test_key_generation()
test_signcryption()
test_unsigncryption()
