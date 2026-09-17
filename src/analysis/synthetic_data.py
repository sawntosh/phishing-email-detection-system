"""
Synthetic email corpus generator for reproducible offline model training.

IMPORTANT / for the report: this sandbox has no network access to real
phishing corpora (e.g. Nazario, PhishTank, Enron-Spam) at build time, so
a template-based synthetic generator is used to produce a reproducible
demo dataset. Document this honestly in the report as a limitation --
Section 5/6 should note that before real deployment the model should be
retrained on an authorised, ethically-sourced corpus such as Nazario's
phishing corpus or the Enron-Spam legitimate-mail set, and the held-out
evaluation in this report should be read as a proof-of-pipeline result,
not a claim of real-world accuracy. scripts/retrain_on_real_corpus.py
(README) documents how to swap the data source without touching the
feature/model code.
"""
import random

PHISH_SUBJECTS = [
    "Urgent: Verify your account now",
    "Your account will be suspended within 24 hours",
    "Unusual activity detected - action required",
    "Final notice: confirm your identity",
    "Your PayPal account has been limited",
    "Security Alert: unauthorized login attempt",
    "Re: Invoice payment overdue - act now",
    "Your parcel could not be delivered - click here",
]

PHISH_BODIES = [
    "Dear Customer, we detected unusual activity on your account. Click here immediately to verify your identity or your account will be suspended within 24 hours. {url}",
    "URGENT ACTION REQUIRED! Your account has been locked due to suspicious activity. Confirm your password and login credentials now: {url}",
    "Dear valued customer, this is your final notice. Update your billing information immediately at {url} to avoid account closure.",
    "We could not verify your identity. Please provide your social security number and credit card details at {url} within 24 hours.",
]

PHISH_SENDER_DOMAINS = [
    "paypa1-secure.com", "micros0ft-support.net", "appleid-verify.xyz",
    "amaz0n-alerts.top", "security-update.click", "192.168.5.7",
]

LEGIT_SUBJECTS = [
    "Team meeting notes - Q3 planning",
    "Your monthly statement is ready",
    "Re: project timeline update",
    "Lunch on Friday?",
    "Invoice #4821 attached",
    "Weekly newsletter - product updates",
]

LEGIT_BODIES = [
    "Hi team, attaching the notes from today's meeting. Let me know if I missed anything.",
    "Hello, your statement for this month is now available in your online banking portal. No action is required if the details look correct.",
    "Hi, just checking in on the project timeline discussed last week. Can we sync tomorrow?",
    "Hey, are you free for lunch on Friday around 12:30? Let me know.",
    "Please find attached invoice #4821 for services rendered in August.",
]

LEGIT_SENDER_DOMAINS = ["company.com", "university.edu.au", "outlook.com", "gmail.com", "vendor-corp.com"]


def _fake_auth_header(pass_all=True):
    if pass_all:
        return "spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"
    return "spf=fail smtp.mailfrom=spoofed.com; dkim=fail header.d=spoofed.com; dmarc=fail"


def generate_synthetic_sample(is_phish: bool, rng: random.Random):
    if is_phish:
        subject = rng.choice(PHISH_SUBJECTS)  # nosec B311 - synthetic training-data generator, not security/crypto use
        domain = rng.choice(PHISH_SENDER_DOMAINS)  # nosec B311
        url = f"http://{domain}/{'login' if rng.random() > 0.5 else 'verify'}?id={rng.randint(1000,9999)}"  # nosec B311
        body = rng.choice(PHISH_BODIES).format(url=url)
        sender = f"\"Account Security\" <support@{domain}>"
        headers = {"Authentication-Results": _fake_auth_header(pass_all=False)}
        if rng.random() > 0.5:
            headers["Reply-To"] = f"reply@{rng.choice(PHISH_SENDER_DOMAINS)}"
        label = 1
    else:
        subject = rng.choice(LEGIT_SUBJECTS)
        domain = rng.choice(LEGIT_SENDER_DOMAINS)
        body = rng.choice(LEGIT_BODIES)
        if rng.random() > 0.6:
            body += f" More details: https://{domain}/portal"
        sender = f"\"Jordan Lee\" <jordan@{domain}>"
        headers = {"Authentication-Results": _fake_auth_header(pass_all=True)}
        label = 0

    return {
        "subject": subject,
        "body_text": body,
        "sender_raw": sender,
        "raw_headers": headers,
        "attachment_count": rng.choice([0, 0, 0, 1]),
        "label": label,
    }


def generate_dataset(n_per_class=350, seed=42):
    rng = random.Random(seed)  # nosec B311 - deterministic, reproducible synthetic dataset generation; not a security context
    samples = []
    for _ in range(n_per_class):
        samples.append(generate_synthetic_sample(True, rng))
        samples.append(generate_synthetic_sample(False, rng))
    rng.shuffle(samples)
    return samples
