import os
import hmac
import hashlib
import secrets
from datetime import date
from html import escape

from lxml import etree
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


PLANS = {"basic": 199, "pro": 499, "team": 999}
GST = 0.18
TRIAL_DAYS = 14
MAX_ATTEMPTS = 3

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
if not WEBHOOK_SECRET:
    raise RuntimeError(
        "WEBHOOK_SECRET environment variable is not set"
    )

CARD_KEY = b"billing-key-1234"


subscriptions = {}

coupons = {
    "WELCOME10": {
        "percent": 10,
        "expires": date(2026, 12, 31),
    },
    "FRIENDS150": {
        "percent": 150,
        "expires": date(2027, 1, 31),
    },
}


def subscribe(user, plan, start):
    """Create a subscription for a user."""
    if plan not in PLANS:
        raise ValueError("Invalid subscription plan")

    subscriptions[user] = {
        "plan": plan,
        "start": start,
        "status": "trial",
        "invoices": [],
    }
    return subscriptions[user]


def isTrialOver(user, today):
    """Check whether the user's trial period has ended."""
    return (
        today - subscriptions[user]["start"]
    ).days > TRIAL_DAYS


def applyCoupon(amount, code, today):
    """Apply a valid coupon without allowing a negative amount."""
    coupon = coupons.get(code)

    if coupon is None:
        return amount

    if today >= coupon["expires"]:
        return amount

    discount = min(coupon["percent"], 100)
    return amount - amount * discount / 100


def invoiceAmount(user, code=None, today=None):
    """Calculate the invoice amount including tax."""
    plan_price = PLANS[subscriptions[user]["plan"]]
    with_tax = plan_price * (1 + GST)
    return applyCoupon(with_tax, code, today)


def nextBillingDate(current):
    """Calculate the next billing date, including December rollover."""
    if current.month == 12:
        return current.replace(
            year=current.year + 1,
            month=1,
        )

    return current.replace(month=current.month + 1)


def prorateUpgrade(user, new_plan, today, period_end):
    """Calculate the prorated price for a plan upgrade."""
    if new_plan not in PLANS:
        raise ValueError("Invalid subscription plan")

    old = PLANS[subscriptions[user]["plan"]]
    new = PLANS[new_plan]
    days_left = max(0, (period_end - today).days)

    subscriptions[user]["plan"] = new_plan
    return (new - old) * days_left / 30


def retryPayment(charge):
    """Retry a payment up to the configured maximum attempts."""
    attempts = 0

    while attempts < MAX_ATTEMPTS:
        attempts += 1

        if charge():
            return attempts

    return attempts


def cancelRefund(user, days_used):
    """Calculate a prorated refund for unused subscription days."""
    if not 0 <= days_used <= 30:
        raise ValueError("Days used must be between 0 and 30")

    price = PLANS[subscriptions[user]["plan"]]
    unused_days = 30 - days_used
    return price * unused_days / 30


def couponCode():
    """Generate a coupon code using a secure random generator."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "SAVE-" + "".join(
        secrets.choice(alphabet) for _ in range(6)
    )


def activeUsers():
    """Return users who have no invoices."""
    return {
        user
        for user, subscription in subscriptions.items()
        if not subscription["invoices"]
    }


def encryptCard(card_number):
    """Encrypt a card number using AES-CBC with a random IV."""
    key = hashlib.sha256(CARD_KEY).digest()
    iv = secrets.token_bytes(16)

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(
        card_number.encode("utf-8")
    ) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    )
    encryptor = cipher.encryptor()

    ciphertext = (
        encryptor.update(padded_data)
        + encryptor.finalize()
    )

    return (iv + ciphertext).hex()


def verifyWebhook(body, signature):
    """Verify a webhook signature using constant-time comparison."""
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def parseWebhook(xml_bytes):
    """Parse an XML webhook payload."""
    root = etree.fromstring(xml_bytes)

    return {
        "event": root.findtext("event"),
        "user": root.findtext("user"),
    }


def renderInvoice(user, amount):
    """Render an invoice with HTML-escaped user input."""
    if amount < 0:
        raise ValueError("Invoice amount cannot be negative")

    safe_user = escape(str(user))
    return (
        f"<h1>Invoice for {safe_user}</h1>"
        f"<p>Total: Rs.{amount}</p>"
    )


def main():
    subscribe("asha", "pro", date(2026, 9, 1))
    subscribe(
        "<b onmouseover=alert(1)>ravi</b>",
        "basic",
        date(2026, 9, 20),
    )

    print(
        "Trial (14 days from 09-01) over on 09-15?",
        isTrialOver("asha", date(2026, 9, 15)),
    )
    print(
        "Pro invoice with WELCOME10:",
        invoiceAmount("asha", "WELCOME10", date(2026, 10, 1)),
    )
    print(
        "Pro invoice with FRIENDS150:",
        invoiceAmount("asha", "FRIENDS150", date(2026, 10, 1)),
    )
    print(
        "Coupon on its expiry day:",
        invoiceAmount("asha", "WELCOME10", date(2026, 12, 31)),
    )
    print(
        "Next billing after 2026-10-15:",
        nextBillingDate(date(2026, 10, 15)),
    )
    print(
        "Upgrade pro->team with 10 days left in Feb:",
        prorateUpgrade(
            "asha",
            "team",
            date(2027, 2, 18),
            date(2027, 2, 28),
        ),
    )

    calls = []
    print(
        "Payment attempts (max 3, always failing):",
        retryPayment(lambda: calls.append(1) and False),
    )
    print(
        "Refund after using 25 of 30 days:",
        cancelRefund("asha", 25),
    )

    encrypted1 = encryptCard("4111111111111111")
    encrypted2 = encryptCard("4111111111111111")
    print(
        "Same card, same ciphertext?",
        encrypted1 == encrypted2,
    )

    signature = hmac.new(
        WEBHOOK_SECRET.encode(),
        b"<x/>",
        hashlib.sha256,
    ).hexdigest()

    print(
        "Webhook verified:",
        verifyWebhook(b"<x/>", signature),
    )
    print(
        "Webhook:",
        parseWebhook(
            b"<hook><event>paid</event><user>asha</user></hook>"
        ),
    )
    print(
        "Invoice HTML:",
        renderInvoice("<b onmouseover=alert(1)>ravi</b>", 199),
    )
    print("Coupon:", couponCode())


if __name__ == "__main__":
    main()