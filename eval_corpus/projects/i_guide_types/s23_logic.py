from flask import request

def apply_discount():
    price = int(request.form["price"])
    qty = int(request.form["qty"])
    # 음수 수량 검증 없음 — 환불 유발
    total = price * qty
    return charge(total)

def transfer():
    amount = float(request.form["amount"])
    src, dst = request.form["src"], request.form["dst"]
    # 잔액 확인과 출금 사이에 검증 없음
    withdraw(src, amount)
    deposit(dst, amount)
