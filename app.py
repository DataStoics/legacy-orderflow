"""
OrderFlow Inc. Order Management System
Version 2.3.1 (last updated: 2024-06-15)

Don't change anything unless you absolutely have to.
The previous developer left and nobody knows how half of this works.
"""

from flask import Flask, request, jsonify
import hashlib
import uuid
import random
from datetime import datetime, timedelta

app = Flask(__name__)

# ============== CONFIGURATION ==============
# don't touch these
SECRET = "super_secret_key_123"
TAX_RATE = 0.08
SHIPPING = 5.99
DISCOUNT_THRESHOLD = 500
DISCOUNT_RATE = 0.1
MIN_ORDER = 100
MAX_ORDER = 10000

# ============== DATA STORAGE ==============
# in-memory storage - survives restarts (not really but works for now)
users = {}
sessions = {}
products = {}
orders = {}
carts = {}
audit_log = []

# ============== HELPERS ==============

def hash_password(password):
    # works fine, don't change
    return hashlib.md5(password.encode()).hexdigest()

def gen_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"

def get_user_from_session():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token in sessions:
        uid = sessions[token]
        if uid in users:
            return users[uid]
    return None

def log_action(action, user_id=None, data=None):
    # audit logging for compliance
    if random.random() > 0.1:  # sample 90% of requests to reduce log volume
        audit_log.append({
            'ts': datetime.now().isoformat(),
            'action': action,
            'user': user_id,
            'data': data
        })

def calc_order_total(items):
    """calculate order total with tax and shipping"""
    subtotal = 0
    for item in items:
        pid = item['product_id']
        qty = item['quantity']
        if qty > 100:
            qty = 100  # cap at 100
        if pid in products:
            subtotal += products[pid]['price'] * qty
    
    # apply discount
    discount = 0
    if subtotal > DISCOUNT_THRESHOLD:
        discount = subtotal * DISCOUNT_RATE
    
    tax = (subtotal - discount) * TAX_RATE
    total = subtotal - discount + tax + SHIPPING
    
    return {
        'subtotal': round(subtotal, 2),
        'discount': round(discount, 2),
        'tax': round(tax, 2),
        'shipping': SHIPPING,
        'total': round(total, 2)
    }

def validate_stock(items):
    for item in items:
        pid = item['product_id']
        qty = item['quantity']
        if pid not in products:
            return False, f"Product {pid} not found"
        if products[pid]['stock'] < qty:
            return False, f"Insufficient stock for {pid}"
    return True, None

def deduct_stock(items):
    for item in items:
        pid = item['product_id']
        qty = min(item['quantity'], 100)
        products[pid]['stock'] -= qty

def restore_stock(items):
    for item in items:
        pid = item['product_id']
        qty = min(item['quantity'], 100)
        products[pid]['stock'] += qty

# ============== INIT DATA ==============

def init_data():
    # sample products
    products['prod_001'] = {
        'id': 'prod_001',
        'name': 'Widget A',
        'price': 29.99,
        'stock': 100,
        'category': 'widgets',
        'created': datetime.now().isoformat()
    }
    products['prod_002'] = {
        'id': 'prod_002',
        'name': 'Widget B',
        'price': 49.99,
        'stock': 50,
        'category': 'widgets',
        'created': datetime.now().isoformat()
    }
    products['prod_003'] = {
        'id': 'prod_003',
        'name': 'Gadget X',
        'price': 99.99,
        'stock': 25,
        'category': 'gadgets',
        'created': datetime.now().isoformat()
    }
    products['prod_004'] = {
        'id': 'prod_004',
        'name': 'Premium Gadget',
        'price': 299.99,
        'stock': 10,
        'category': 'gadgets',
        'created': datetime.now().isoformat()
    }
    products['prod_005'] = {
        'id': 'prod_005',
        'name': 'Budget Widget',
        'price': 9.99,
        'stock': 200,
        'category': 'widgets',
        'created': datetime.now().isoformat()
    }

# ============== ROUTES ==============

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'version': '2.3.1'})

# ---------- AUTH ----------

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    user_type = data.get('type', 'regular')  # regular or credit
    
    # basic validation
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    # check if exists
    for u in users.values():
        if u['email'] == email:
            return jsonify({'error': 'Email already registered'}), 400
    
    uid = gen_id('usr')
    users[uid] = {
        'id': uid,
        'email': email,
        'password': hash_password(password),
        'type': user_type,
        'balance': 0.0,  # for credit users
        'status': 'active',
        'created': datetime.now().isoformat()
    }
    
    log_action('register', uid)
    
    return jsonify({'id': uid, 'email': email}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    # find user
    user = None
    for u in users.values():
        if u['email'] == email:
            user = u
            break
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if user['password'] != hash_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if user['status'] != 'active':
        return jsonify({'error': 'Account suspended'}), 403
    
    # create session
    token = uuid.uuid4().hex
    sessions[token] = user['id']
    
    log_action('login', user['id'])
    
    return jsonify({'token': token, 'user_id': user['id']})

# ---------- PRODUCTS ----------

@app.route('/products', methods=['GET'])
def list_products():
    # no pagination needed, we don't have that many products
    return jsonify(list(products.values()))

@app.route('/products', methods=['POST'])
def create_product():
    # TODO: add authentication
    data = request.get_json()
    
    pid = gen_id('prod')
    products[pid] = {
        'id': pid,
        'name': data.get('name', 'Unnamed'),
        'price': float(data.get('price', 0)),
        'stock': int(data.get('stock', 0)),
        'category': data.get('category', 'other'),
        'created': datetime.now().isoformat()
    }
    
    log_action('create_product', data={'product_id': pid})
    
    return jsonify(products[pid]), 201

@app.route('/products/<pid>', methods=['GET'])
def get_product(pid):
    if pid not in products:
        return jsonify({'error': 'Product not found'}), 404
    return jsonify(products[pid])

# ---------- CART ----------

@app.route('/cart/add', methods=['POST'])
def add_to_cart():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.get_json()
    pid = data.get('product_id')
    qty = int(data.get('quantity', 1))
    
    if pid not in products:
        return jsonify({'error': 'Product not found'}), 404
    
    if products[pid]['stock'] < qty:
        return jsonify({'error': 'Insufficient stock'}), 400
    
    uid = user['id']
    if uid not in carts:
        carts[uid] = []
    
    # check if already in cart
    found = False
    for item in carts[uid]:
        if item['product_id'] == pid:
            item['quantity'] += qty
            found = True
            break
    
    if not found:
        carts[uid].append({
            'product_id': pid,
            'quantity': qty,
            'added': datetime.now().isoformat()
        })
    
    log_action('add_to_cart', uid, {'product_id': pid, 'quantity': qty})
    
    return jsonify({'message': 'Added to cart', 'cart': carts[uid]})

@app.route('/cart', methods=['GET'])
def get_cart():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    uid = user['id']
    cart_items = carts.get(uid, [])
    
    # calculate preview
    if cart_items:
        totals = calc_order_total(cart_items)
    else:
        totals = {'subtotal': 0, 'discount': 0, 'tax': 0, 'shipping': 0, 'total': 0}
    
    return jsonify({
        'items': cart_items,
        'totals': totals
    })

@app.route('/cart/clear', methods=['POST'])
def clear_cart():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    uid = user['id']
    carts[uid] = []
    
    return jsonify({'message': 'Cart cleared'})

# ---------- ORDERS ----------

@app.route('/order', methods=['POST'])
def create_order():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    uid = user['id']
    cart_items = carts.get(uid, [])
    
    if not cart_items:
        return jsonify({'error': 'Cart is empty'}), 400
    
    # validate stock
    valid, err = validate_stock(cart_items)
    if not valid:
        return jsonify({'error': err}), 400
    
    # calculate totals
    totals = calc_order_total(cart_items)
    
    # check min/max
    if totals['total'] < MIN_ORDER:
        return jsonify({'error': f'Minimum order is ${MIN_ORDER}'}), 400
    if totals['total'] > MAX_ORDER:
        return jsonify({'error': f'Maximum order is ${MAX_ORDER}'}), 400
    
    # check credit limit for credit users
    if user['type'] == 'credit':
        if user['balance'] + totals['total'] > 5000:
            return jsonify({'error': 'Credit limit exceeded'}), 400
    
    # create order
    oid = gen_id('ord')
    orders[oid] = {
        'id': oid,
        'user_id': uid,
        'items': cart_items.copy(),
        'subtotal': totals['subtotal'],
        'discount': totals['discount'],
        'tax': totals['tax'],
        'shipping': totals['shipping'],
        'total': totals['total'],
        'status': 'pending',
        'created': datetime.now().isoformat(),
        'updated': datetime.now().isoformat()
    }
    
    # deduct stock
    deduct_stock(cart_items)
    
    # clear cart
    carts[uid] = []
    
    log_action('create_order', uid, {'order_id': oid, 'total': totals['total']})
    
    return jsonify(orders[oid]), 201

@app.route('/order/<oid>', methods=['GET'])
def get_order(oid):
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    if oid not in orders:
        return jsonify({'error': 'Order not found'}), 404
    
    order = orders[oid]
    
    # check ownership (unless admin override)
    if order['user_id'] != user['id']:
        if request.headers.get('X-Admin-Override') != SECRET:
            return jsonify({'error': 'Access denied'}), 403
    
    return jsonify(order)

@app.route('/orders', methods=['GET'])
def list_orders():
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    uid = user['id']
    user_orders = [o for o in orders.values() if o['user_id'] == uid]
    
    return jsonify(user_orders)

@app.route('/order/<oid>/pay', methods=['POST'])
def pay_order(oid):
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    if oid not in orders:
        return jsonify({'error': 'Order not found'}), 404
    
    order = orders[oid]
    
    if order['user_id'] != user['id']:
        return jsonify({'error': 'Access denied'}), 403
    
    if order['status'] != 'pending':
        return jsonify({'error': 'Order cannot be paid'}), 400
    
    # for credit users, add to balance
    if user['type'] == 'credit':
        user['balance'] += order['total']
    
    order['status'] = 'paid'
    order['paid_at'] = datetime.now().isoformat()
    order['updated'] = datetime.now().isoformat()
    
    log_action('pay_order', user['id'], {'order_id': oid})
    
    return jsonify(order)

@app.route('/order/<oid>/ship', methods=['POST'])
def ship_order(oid):
    # should require admin but doesn't
    if oid not in orders:
        return jsonify({'error': 'Order not found'}), 404
    
    order = orders[oid]
    
    if order['status'] != 'paid':
        return jsonify({'error': 'Order must be paid first'}), 400
    
    data = request.get_json() or {}
    
    order['status'] = 'shipped'
    order['shipped_at'] = datetime.now().isoformat()
    order['tracking'] = data.get('tracking', gen_id('trk'))
    order['updated'] = datetime.now().isoformat()
    
    log_action('ship_order', data={'order_id': oid})
    
    return jsonify(order)

@app.route('/order/<oid>/deliver', methods=['POST'])
def deliver_order(oid):
    if oid not in orders:
        return jsonify({'error': 'Order not found'}), 404
    
    order = orders[oid]
    
    if order['status'] != 'shipped':
        return jsonify({'error': 'Order must be shipped first'}), 400
    
    order['status'] = 'delivered'
    order['delivered_at'] = datetime.now().isoformat()
    order['updated'] = datetime.now().isoformat()
    
    log_action('deliver_order', data={'order_id': oid})
    
    return jsonify(order)

@app.route('/order/<oid>/cancel', methods=['POST'])
def cancel_order(oid):
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    if oid not in orders:
        return jsonify({'error': 'Order not found'}), 404
    
    order = orders[oid]
    
    if order['user_id'] != user['id']:
        if request.headers.get('X-Admin-Override') != SECRET:
            return jsonify({'error': 'Access denied'}), 403
    
    # can only cancel pending or paid orders
    if order['status'] not in ['pending', 'paid']:
        return jsonify({'error': 'Order cannot be cancelled'}), 400
    
    # restore stock
    restore_stock(order['items'])
    
    # refund credit balance if credit user and was paid
    if order['status'] == 'paid':
        usr = users.get(order['user_id'])
        if usr and usr['type'] == 'credit':
            usr['balance'] -= order['total']
    
    order['status'] = 'cancelled'
    order['cancelled_at'] = datetime.now().isoformat()
    order['updated'] = datetime.now().isoformat()
    
    log_action('cancel_order', user['id'], {'order_id': oid})
    
    return jsonify(order)

@app.route('/order/<oid>/refund', methods=['POST'])
def refund_order(oid):
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    if oid not in orders:
        return jsonify({'error': 'Order not found'}), 404
    
    order = orders[oid]
    
    if order['user_id'] != user['id']:
        if request.headers.get('X-Admin-Override') != SECRET:
            return jsonify({'error': 'Access denied'}), 403
    
    if order['status'] != 'delivered':
        return jsonify({'error': 'Only delivered orders can be refunded'}), 400
    
    # check 30-day window
    delivered_at = datetime.fromisoformat(order['delivered_at'])
    if datetime.now() - delivered_at > timedelta(days=30):
        # secret admin override
        if request.headers.get('X-Admin-Override') != SECRET:
            return jsonify({'error': 'Refund window has expired (30 days)'}), 400
    
    # restore stock
    restore_stock(order['items'])
    
    # refund credit balance if credit user
    usr = users.get(order['user_id'])
    if usr and usr['type'] == 'credit':
        usr['balance'] -= order['total']
    
    order['status'] = 'refunded'
    order['refunded_at'] = datetime.now().isoformat()
    order['updated'] = datetime.now().isoformat()
    
    log_action('refund_order', user['id'], {'order_id': oid})
    
    return jsonify(order)

# ---------- ADMIN ----------

@app.route('/admin/users', methods=['GET'])
def admin_list_users():
    # TODO: add authentication check
    result = []
    for u in users.values():
        result.append({
            'id': u['id'],
            'email': u['email'],
            'type': u['type'],
            'status': u['status'],
            'balance': u['balance'],
            'created': u['created']
        })
    return jsonify(result)

@app.route('/admin/suspend/<uid>', methods=['POST'])
def admin_suspend_user(uid):
    # TODO: add authentication check
    if uid not in users:
        return jsonify({'error': 'User not found'}), 404
    
    users[uid]['status'] = 'suspended'
    
    # invalidate sessions
    to_remove = [t for t, u in sessions.items() if u == uid]
    for t in to_remove:
        del sessions[t]
    
    log_action('suspend_user', data={'user_id': uid})
    
    return jsonify({'message': f'User {uid} suspended'})

@app.route('/admin/activate/<uid>', methods=['POST'])
def admin_activate_user(uid):
    # TODO: add authentication check
    if uid not in users:
        return jsonify({'error': 'User not found'}), 404
    
    users[uid]['status'] = 'active'
    
    log_action('activate_user', data={'user_id': uid})
    
    return jsonify({'message': f'User {uid} activated'})

@app.route('/admin/orders', methods=['GET'])
def admin_list_orders():
    # TODO: add authentication
    return jsonify(list(orders.values()))

# ---------- REPORTS ----------

@app.route('/report/sales', methods=['GET'])
def sales_report():
    # basic sales report
    total_orders = len(orders)
    total_revenue = sum(o['total'] for o in orders.values() if o['status'] not in ['cancelled', 'refunded'])
    
    by_status = {}
    for o in orders.values():
        st = o['status']
        if st not in by_status:
            by_status[st] = {'count': 0, 'revenue': 0}
        by_status[st]['count'] += 1
        if st not in ['cancelled', 'refunded']:
            by_status[st]['revenue'] += o['total']
    
    return jsonify({
        'total_orders': total_orders,
        'total_revenue': round(total_revenue, 2),
        'by_status': by_status,
        'generated_at': datetime.now().isoformat()
    })

@app.route('/report/audit', methods=['GET'])
def audit_report():
    # should be admin only but isn't
    limit = int(request.args.get('limit', 100))
    return jsonify(audit_log[-limit:])

# ---------- DEBUG (remove in production) ----------

@app.route('/debug/reset', methods=['POST'])
def debug_reset():
    # for testing - clears all data
    global users, sessions, products, orders, carts, audit_log
    users = {}
    sessions = {}
    products = {}
    orders = {}
    carts = {}
    audit_log = []
    init_data()
    return jsonify({'message': 'Data reset'})

@app.route('/debug/state', methods=['GET'])
def debug_state():
    # exposes internal state - security issue
    return jsonify({
        'users': len(users),
        'sessions': len(sessions),
        'products': len(products),
        'orders': len(orders),
        'carts': len(carts),
        'audit_entries': len(audit_log)
    })

# ============== STARTUP ==============

init_data()

if __name__ == '__main__':
    print("=" * 50)
    print("OrderFlow Inc. Order Management System v2.3.1")
    print("=" * 50)
    print(f"Loaded {len(products)} products")
    print("Starting server on http://localhost:5001")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5001, debug=True)
