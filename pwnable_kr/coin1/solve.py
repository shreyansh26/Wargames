from pwn import *
from time import sleep
import string

# This is slow, update to pwnable.kr server using some other login and use with host = "0"
p = remote("pwnable.kr", 9007)

def ltos(a):
    return ' '.join(a)

def getLists(a):
    x = len(a)//2
    return a[:x], a[x:]

x = p.recvuntil("... -")
#sleep(3)

p.recvline()
NUM_ROUNDS = 100
p.recvline()
for _ in range(NUM_ROUNDS):
    a = p.recvline().strip()
    print(a)
    x,y = a.split(' ')
    n = int(x.split('N=')[1])
    c = int(y.split('C=')[1])

    print(n, c)

    total = list(range(0, n))
    for i in range(len(total)):
        total[i] = str(total[i])
    l1, l2 = getLists(total)
    cnt = 1
    ans = -1
    flag = 0
    while cnt <= c:
        if len(l1) == 0:
            ans = ltos(l2)
            while cnt <= c:
                p.sendline(ans)
                print(ans)
                a = p.recvline().strip()
                print(a)
                cnt += 1
            p.sendline(ans)
            print(ans)
            a = p.recvline().strip()
            print(a)
       
        if ltos(l1).strip() == "":
            if "Correct" in a:
                break
        sending = ltos(l1)
        p.sendline(sending)
        print(sending)
        a = p.recvline().strip()
        print(a)

        ##try:
        a = int(a)
        if a == 9:
            ans = sending
        if a % 10 == 0:
            l1, l2 = getLists(l2)
        else:
            l1, l2 = getLists(l1)
        
        if ans != -1:
            while cnt <= c:
                p.sendline(ans)
                print(ans)
                a = p.recvline().strip()
                print(a)
                cnt += 1
        if cnt == c:
            if a == 10:
                ans = l2[-1]
            p.sendline(ans)
            print(ans)
            a = p.recvline().strip()
        ##except ValueError:
        cnt += 1
    ##print(p.recvline())

print(p.recvline())
print(p.recvline())
p.close()
