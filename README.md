# SETLA KEM Implementation
Реализация схемы шифрования и подписи SETLA KEM на языке Python. 
Оригинальная статья: https://eprint.iacr.org/2018/056.

Для работы необходим python3 со следующими библиотеками:
-   **SageMath** (https://www.sagemath.org/): используется для реализации самой схемы 
    SETLA KEM;
-   **pycrypto** (https://pypi.org/project/pycrypto/): используется для работы с алгоритмом
    AES, выбранном в качестве симметричного алгоритма шифрования;
-   **Pympler** (https://pypi.org/project/Pympler/): используется для вычисления размера
    объектов python в байтах.