import threading
count = 0

def add():
    global count
    tmp = count
    count = tmp + 1

def withdraw(acc, amt):
    if balance(acc) >= amt:
        do_withdraw(acc, amt)
