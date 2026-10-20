# API views for ShopIndia
# All PII handling matches privacy policy disclosures

from models.user import User, Order
from services.notifications import send_order_confirmation

def register_user(request):
    data = request.POST
    user = User.objects.create(
        full_name    = data['full_name'],
        email        = data['email'],
        phone_number = data['phone_number'],
        address      = data['address'],
    )
    return {"status": "registered", "id": user.id}


def place_order(request):
    data    = request.POST
    user    = User.objects.get(id=data['user_id'])
    order   = Order.objects.create(
        user    = user,
        product = data['product'],
        amount  = data['amount'],
    )
    send_order_confirmation(user)
    return {"status": "ordered", "order_id": order.id}
