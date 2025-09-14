from flask import Flask, render_template, request, session, redirect, url_for
import random
import math
from math import gcd
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def find_nearest_primes(day):
    # Tìm số nguyên tố gần ngày sinh
    p = day
    q = day
    
    # Tìm số nguyên tố nhỏ hơn
    while p > 2 and not is_prime(p):
        p -= 1
    
    # Tìm số nguyên tố lớn hơn
    while not is_prime(q):
        q += 1
    
    return p, q

def mod_inverse(a, m):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        return None
    return (x % m + m) % m

def generate_keys(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Cả P và Q phải là số nguyên tố')
    
    n = p * q
    phi = (p-1) * (q-1)
    
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    
    d = mod_inverse(e, phi)
    
    if d is None:
        raise ValueError('Không thể tìm khóa nghịch đảo')
    
    return ((e, n), (d, n))

def text_to_numbers(text):
    # Chuyển văn bản thành chuỗi số (A=65, B=66, ...)
    return [ord(char) for char in text]

def numbers_to_text(numbers):
    # Chuyển chuỗi số thành văn bản
    return ''.join(chr(num) for num in numbers)

def rsa_sign(message, private_key):
    d, n = private_key
    # Chuyển thông điệp thành số
    message_numbers = text_to_numbers(message)
    signature = []
    for num in message_numbers:
        # Đảm bảo số không vượt quá n
        if num >= n:
            raise ValueError(f'Ký tự {chr(num)} có giá trị {num} vượt quá n={n}')
        signature.append(pow(num, d, n))
    return signature

def rsa_verify(signature, public_key):
    e, n = public_key
    
    # Giải mã chữ ký
    decrypted_numbers = []
    for sig in signature:
        decrypted_numbers.append(pow(sig, e, n))
    
    # Chuyển đổi số đã giải mã thành văn bản
    decrypted_message = numbers_to_text(decrypted_numbers)
    
    return decrypted_message, decrypted_numbers

@app.template_filter('ord')
def ord_filter(char):
    return ord(char)

@app.route('/', methods=['GET', 'POST'])
def index():
    private_key = session.get('private_key')
    public_key = session.get('public_key')
    signature = session.get('signature')
    verification_result = session.get('verification_result')
    decrypted_message = session.get('decrypted_message')
    decrypted_numbers = session.get('decrypted_numbers')
    p = session.get('p')
    q = session.get('q')
    message = session.get('message', 'NGUYENVANA')
    birth_date = session.get('birth_date', '2000-01-01')
    message_numbers = session.get('message_numbers', [])
    
    # Xóa các giá trị trong session sau khi đã sử dụng
    if 'error' in session:
        error = session['error']
        session.pop('error')
    else:
        error = None
    
    return render_template('index.html', 
                         private_key=private_key, 
                         public_key=public_key,
                         signature=signature,
                         verification_result=verification_result,
                         decrypted_message=decrypted_message,
                         decrypted_numbers=decrypted_numbers,
                         p=p, q=q, message=message, birth_date=birth_date,
                         message_numbers=message_numbers,
                         error=error)

@app.route('/generate', methods=['POST'])
def generate():
    try:
        birth_date = request.form['birth_date']
        message = request.form['message']
        session['birth_date'] = birth_date
        session['message'] = message
        
        # Lấy ngày từ ngày sinh
        day = int(birth_date.split('-')[2])
        
        p, q = find_nearest_primes(day)
        
        public_key, private_key = generate_keys(p, q)
        
        # Chuyển đổi message thành dạng số
        message_numbers = text_to_numbers(message)
        
        session['private_key'] = private_key
        session['public_key'] = public_key
        session['p'] = p
        session['q'] = q
        session['message_numbers'] = message_numbers
        
        # Xóa chữ ký cũ khi sinh khóa mới
        if 'signature' in session:
            session.pop('signature')
        if 'verification_result' in session:
            session.pop('verification_result')
        if 'decrypted_message' in session:
            session.pop('decrypted_message')
        if 'decrypted_numbers' in session:
            session.pop('decrypted_numbers')
        
    except Exception as e:
        session['error'] = f'Lỗi khi sinh khóa: {str(e)}'
    
    return redirect(url_for('index'))

@app.route('/sign', methods=['POST'])
def sign():
    if 'private_key' not in session:
        session['error'] = 'Chưa sinh khóa. Vui lòng chọn ngày sinh trước'
        return redirect(url_for('index'))
    
    try:
        message = request.form['message']
        private_key = session['private_key']
        
        signature = rsa_sign(message, private_key)
        session['signature'] = signature
        session['message'] = message
        
        # Chuyển đổi message thành dạng số
        message_numbers = text_to_numbers(message)
        session['message_numbers'] = message_numbers
        
        # Xóa kết quả xác thực cũ
        if 'verification_result' in session:
            session.pop('verification_result')
        if 'decrypted_message' in session:
            session.pop('decrypted_message')
        if 'decrypted_numbers' in session:
            session.pop('decrypted_numbers')
        
    except Exception as e:
        session['error'] = f'Lỗi khi ký văn bản: {str(e)}'
    
    return redirect(url_for('index'))

@app.route('/verify', methods=['POST'])
def verify():
    if 'public_key' not in session:
        session['error'] = 'Chưa sinh khóa. Vui lòng chọn ngày sinh trước'
        return redirect(url_for('index'))
    
    try:
        signature_input = request.form['verify_signature']
        
        # Chuyển đổi chữ ký từ chuỗi thành list số
        signature = []
        if signature_input:
            # Xử lý chuỗi chữ ký (loại bỏ dấu ngoặc và khoảng trắng)
            signature_input = signature_input.strip().replace('[', '').replace(']', '')
            signature = [int(x.strip()) for x in signature_input.split(',') if x.strip()]
        
        public_key = session['public_key']
        
        # Giải mã chữ ký để lấy văn bản và các số đã giải mã
        decrypted_message, decrypted_numbers = rsa_verify(signature, public_key)
        session['decrypted_message'] = decrypted_message
        session['decrypted_numbers'] = decrypted_numbers
        
        # Kiểm tra xem chữ ký có hợp lệ không (so với message đã ký trước đó nếu có)
        original_message = session.get('message', '')
        is_valid = (decrypted_message == original_message)
        session['verification_result'] = is_valid
        
    except Exception as e:
        session['error'] = f'Lỗi khi xác thực chữ ký: {str(e)}'
        session['verification_result'] = False
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)