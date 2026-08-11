import re
from urllib.parse import urlparse


class ScamModel:

    def __init__(self):
        print("ScamShield AI model loaded successfully.")

    # =========================================================
    # MAIN ANALYZER
    # =========================================================

    def analyze(self, content_type, text):

        text = (text or "").strip()

        if not text:
            return {
                "risk_score": 0,
                "risk_level": "SAFE",
                "summary": "No input provided.",
                "explanations": [
                    "Please enter a message, URL, or product listing."
                ],
                "evidence_tags": ["No Input"],
                "recommendations": [
                    "Enter content to analyze."
                ]
            }

        content_type = content_type.lower().strip()

        if content_type == "url":
            return self.analyze_url(text)

        elif content_type == "ecommerce":
            return self.analyze_ecommerce(text)

        else:
            return self.analyze_message(text)

    # =========================================================
    # MESSAGE / EMAIL / SMS ANALYZER
    # =========================================================

    def analyze_message(self, text):

        lower = text.lower()

        score = 0
        explanations = []
        evidence_tags = []

        # -----------------------------------------------------
        # 1. URGENCY / PRESSURE
        # -----------------------------------------------------

        urgency_words = [
            "urgent",
            "immediately",
            "act now",
            "within 24 hours",
            "within 12 hours",
            "within 48 hours",
            "final warning",
            "final notice",
            "suspended",
            "suspend",
            "locked",
            "lock",
            "deactivated",
            "deactivate",
            "expires",
            "expire",
            "last chance",
            "limited time",
            "deadline",
            "respond now"
        ]

        found_urgency = [
            word for word in urgency_words
            if word in lower
        ]

        if found_urgency:

            score += 25

            evidence_tags.append(
                "Artificial Urgency"
            )

            explanations.append(
                "The message uses urgency or deadline "
                "language to pressure the recipient."
            )

        # -----------------------------------------------------
        # 2. ACCOUNT VERIFICATION
        # -----------------------------------------------------

        verification_words = [
            "verify",
            "verification",
            "verify your account",
            "verify account",
            "confirm",
            "confirmation",
            "confirm your account",
            "confirm account",
            "account verification",
            "identity verification",
            "verify your identity",
            "confirm your identity",
            "account needs verification",
            "account information",
            "security verification",
            "update your account",
            "update account"
        ]

        found_verification = [
            word for word in verification_words
            if word in lower
        ]

        if found_verification:

            score += 30

            evidence_tags.append(
                "Account Verification Request"
            )

            explanations.append(
                "The message asks the recipient to verify "
                "or confirm account or identity information."
            )

        # -----------------------------------------------------
        # 3. CREDENTIAL HARVESTING
        # -----------------------------------------------------

        credential_words = [
            "otp",
            "one time password",
            "one-time password",
            "password",
            "passcode",
            "pin",
            "ssn",
            "social security",
            "credentials",
            "banking details",
            "bank details",
            "card details",
            "credit card",
            "debit card",
            "login details",
            "security code",
            "verification code",
            "authentication code"
        ]

        found_credentials = [
            word for word in credential_words
            if word in lower
        ]

        if found_credentials:

            score += 35

            evidence_tags.append(
                "Credential Harvesting"
            )

            explanations.append(
                "The message requests or encourages "
                "sharing sensitive account information."
            )

        # -----------------------------------------------------
        # 4. FINANCIAL SCAM
        # -----------------------------------------------------

        financial_words = [
            "gift card",
            "giftcard",
            "bitcoin",
            "crypto",
            "cryptocurrency",
            "zelle",
            "venmo",
            "cashapp",
            "wire transfer",
            "bank transfer",
            "processing fee",
            "send money",
            "pay now",
            "payment required",
            "refund fee",
            "claim your prize",
            "lottery",
            "winner",
            "prize",
            "unclaimed money",
            "inheritance"
        ]

        found_financial = [
            word for word in financial_words
            if word in lower
        ]

        if found_financial:

            score += 30

            evidence_tags.append(
                "Financial Scam Signal"
            )

            explanations.append(
                "The message contains suspicious payment, "
                "money-transfer, prize, or financial language."
            )

        # -----------------------------------------------------
        # 5. THREAT / FEAR
        # -----------------------------------------------------

        threat_words = [
            "arrest",
            "warrant",
            "police",
            "lawsuit",
            "legal action",
            "court",
            "terminate",
            "termination",
            "fine",
            "penalty",
            "criminal",
            "investigation"
        ]

        found_threats = [
            word for word in threat_words
            if word in lower
        ]

        if found_threats:

            score += 30

            evidence_tags.append(
                "Threatening Language"
            )

            explanations.append(
                "The message uses threats or legal "
                "consequences to pressure the recipient."
            )

        # -----------------------------------------------------
        # 6. SUSPICIOUS LINK INSIDE MESSAGE
        # -----------------------------------------------------

        urls = re.findall(
            r"https?://[^\s]+|www\.[^\s]+",
            text,
            re.IGNORECASE
        )

        if urls:

            evidence_tags.append(
                "Embedded Link"
            )

            link_result = self._calculate_url_score(
                urls[0]
            )

            if link_result["score"] >= 30:

                score += 30

                evidence_tags.append(
                    "Suspicious Embedded Link"
                )

                explanations.append(
                    "The message contains a link with "
                    "suspicious URL characteristics."
                )

            else:

                score += 5

                explanations.append(
                    "The message contains an embedded link. "
                    "Verify the destination before opening it."
                )

        # =====================================================
        # SMART COMBINATION RULES
        # =====================================================

        # Urgency + verification
        if found_urgency and found_verification:
            score = max(score, 65)

        # Urgency + credentials
        if found_urgency and found_credentials:
            score = max(score, 75)

        # Verification + credentials
        if found_verification and found_credentials:
            score = max(score, 70)

        # Financial + credentials
        if found_credentials and found_financial:
            score = max(score, 80)

        # Urgency + financial
        if found_urgency and found_financial:
            score = max(score, 75)

        # Threat + urgency
        if found_threats and found_urgency:
            score = max(score, 80)

        # Suspicious URL + urgency
        if found_urgency and urls:

            link_result = self._calculate_url_score(
                urls[0]
            )

            if link_result["score"] >= 30:
                score = max(score, 85)

        # Many independent indicators
        if len(evidence_tags) >= 4:
            score = max(score, 85)

        # -----------------------------------------------------
        # IMPORTANT SUSPICIOUS RULE
        # -----------------------------------------------------

        # Account verification alone should be SUSPICIOUS,
        # not SAFE.

        if (
            found_verification
            and not found_urgency
            and not found_credentials
            and not found_financial
            and not found_threats
            and not urls
        ):
            score = max(score, 40)

        # -----------------------------------------------------
        # FINAL MESSAGE SCORE
        # -----------------------------------------------------

        score = min(100, max(0, score))

        risk_level = self.get_risk_level(score)

        if not explanations:

            explanations.append(
                "No major scam indicators were detected "
                "in the provided message."
            )

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "scam_probability": round(score / 100, 2),
            "summary": (
                f"Message assessed as {risk_level} "
                f"with a risk score of {score}/100."
            ),
            "explanations": explanations,
            "evidence_tags": (
                evidence_tags
                if evidence_tags
                else ["No Major Indicator"]
            ),
            "recommendations":
                self.get_message_recommendations(score)
        }

    # =========================================================
    # URL ANALYZER
    # =========================================================

    def analyze_url(self, url):

        result = self._calculate_url_score(url)

        score = result["score"]

        risk_level = self.get_risk_level(score)

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "scam_probability": round(score / 100, 2),
            "summary": (
                f"URL assessed as {risk_level} "
                f"with a risk score of {score}/100."
            ),
            "explanations": result["explanations"],
            "evidence_tags": (
                result["evidence_tags"]
                if result["evidence_tags"]
                else ["Standard Web Domain"]
            ),
            "recommendations":
                self.get_url_recommendations(
                    score,
                    result["domain"]
                )
        }

    # =========================================================
    # URL SCORING ENGINE
    # =========================================================

    def _calculate_url_score(self, url):

        original_url = url.strip()

        # -----------------------------------------------------
        # ADD HTTP IF PROTOCOL IS MISSING
        # -----------------------------------------------------

        if not re.match(
            r"^https?://",
            original_url,
            re.IGNORECASE
        ):

            working_url = "http://" + original_url

        else:

            working_url = original_url

        parsed = urlparse(working_url)

        domain = (
            parsed.hostname or ""
        ).lower()

        path = (
            parsed.path or ""
        ).lower()

        full_url = domain + path

        score = 0

        explanations = []

        evidence_tags = []

        # -----------------------------------------------------
        # INVALID URL
        # -----------------------------------------------------

        if not domain:

            return {
                "score": 70,
                "domain": "unknown",
                "explanations": [
                    "The URL appears to be invalid."
                ],
                "evidence_tags": [
                    "Invalid URL"
                ]
            }

        # -----------------------------------------------------
        # 1. RAW IP ADDRESS
        # -----------------------------------------------------

        if re.match(
            r"^\d{1,3}(\.\d{1,3}){3}$",
            domain
        ):

            score += 45

            evidence_tags.append(
                "Raw IP Hostname"
            )

            explanations.append(
                "The URL uses a raw IP address instead "
                "of a normal domain name."
            )

        # -----------------------------------------------------
        # 2. SUSPICIOUS TLD
        # -----------------------------------------------------

        suspicious_tlds = {
            "xyz",
            "top",
            "tk",
            "ml",
            "ga",
            "cf",
            "gq",
            "click",
            "work",
            "icu",
            "vip",
            "info",
            "online",
            "site",
            "support",
            "live",
            "download",
            "club",
            "buzz"
        }

        domain_parts = domain.split(".")

        if len(domain_parts) >= 2:

            tld = domain_parts[-1]

            if tld in suspicious_tlds:

                score += 30

                evidence_tags.append(
                    f"Suspicious TLD (.{tld})"
                )

                explanations.append(
                    f"The domain uses the .{tld} "
                    "top-level domain, which can be "
                    "associated with disposable or "
                    "suspicious websites."
                )

        # -----------------------------------------------------
        # 3. BRAND IMPERSONATION / TYPOSQUATTING
        # -----------------------------------------------------

        brands = {

            "paypal": {
                "official": "paypal.com",
                "lookalikes": [
                    "paypa1",
                    "paypai",
                    "pay-pal"
                ]
            },

            "amazon": {
                "official": "amazon.com",
                "lookalikes": [
                    "amaz0n",
                    "amazn"
                ]
            },

            "google": {
                "official": "google.com",
                "lookalikes": [
                    "g00gle",
                    "goog1e"
                ]
            },

            "apple": {
                "official": "apple.com",
                "lookalikes": [
                    "app1e"
                ]
            },

            "microsoft": {
                "official": "microsoft.com",
                "lookalikes": [
                    "micros0ft"
                ]
            },

            "instagram": {
                "official": "instagram.com",
                "lookalikes": [
                    "instagrarn",
                    "instagr4m"
                ]
            },

            "facebook": {
                "official": "facebook.com",
                "lookalikes": [
                    "faceb00k"
                ]
            },

            "netflix": {
                "official": "netflix.com",
                "lookalikes": [
                    "netfl1x"
                ]
            },

            "coinbase": {
                "official": "coinbase.com",
                "lookalikes": [
                    "coinbas3"
                ]
            },

            "chase": {
                "official": "chase.com",
                "lookalikes": []
            },

            "wellsfargo": {
                "official": "wellsfargo.com",
                "lookalikes": []
            }
        }

        for brand, data in brands.items():

            official_domain = data["official"]

            # Exact brand in domain
            normal_brand_found = brand in domain

            # Known typo variation
            typo_found = any(
                typo in domain
                for typo in data["lookalikes"]
            )

            if normal_brand_found or typo_found:

                is_official = (
                    domain == official_domain
                    or domain.endswith(
                        "." + official_domain
                    )
                )

                if not is_official:

                    score += 50

                    evidence_tags.append(
                        "Brand Impersonation"
                    )

                    explanations.append(
                        f"The domain appears to imitate "
                        f"{brand.title()} but is not the "
                        "official domain."
                    )

                    break

        # -----------------------------------------------------
        # 4. PHISHING KEYWORDS
        # -----------------------------------------------------

        phishing_words = [
            "login",
            "signin",
            "sign-in",
            "verify",
            "verification",
            "secure",
            "security",
            "account",
            "billing",
            "password",
            "confirm",
            "authorize",
            "authorization",
            "refund",
            "claim",
            "update",
            "support",
            "help",
            "restore"
        ]

        found_phishing = [
            word
            for word in phishing_words
            if word in full_url
        ]

        if found_phishing:

            score += 20

            evidence_tags.append(
                "Phishing URL Keywords"
            )

            explanations.append(
                "The URL contains account, login, "
                "verification, or security keywords "
                "commonly used in phishing links."
            )

        # -----------------------------------------------------
        # 5. HTTP + SECURITY KEYWORD
        # -----------------------------------------------------

        security_words = [
            "login",
            "signin",
            "account",
            "password",
            "verify",
            "bank",
            "billing",
            "secure"
        ]

        if (
            original_url.lower().startswith("http://")
            and any(
                word in full_url
                for word in security_words
            )
        ):

            score += 20

            evidence_tags.append(
                "Unencrypted HTTP"
            )

            explanations.append(
                "The URL uses HTTP instead of HTTPS "
                "for a security-sensitive destination."
            )

        # -----------------------------------------------------
        # 6. MANY HYPHENS
        # -----------------------------------------------------

        if domain.count("-") >= 2:

            score += 10

            evidence_tags.append(
                "Suspicious Domain Structure"
            )

            explanations.append(
                "The domain contains multiple hyphens, "
                "which can be used in deceptive lookalike domains."
            )

        # -----------------------------------------------------
        # 7. LONG / COMPLEX DOMAIN
        # -----------------------------------------------------

        if len(domain) > 35:

            score += 10

            evidence_tags.append(
                "Unusually Long Domain"
            )

            explanations.append(
                "The domain is unusually long and complex."
            )

        # -----------------------------------------------------
        # FINAL URL SCORE
        # -----------------------------------------------------

        score = min(100, max(0, score))

        if not explanations:

            explanations.append(
                "No major URL warning indicators were detected."
            )

        return {
            "score": score,
            "domain": domain,
            "explanations": explanations,
            "evidence_tags": evidence_tags
        }

    # =========================================================
    # E-COMMERCE ANALYZER
    # =========================================================

    def analyze_ecommerce(self, text):

        lower = text.lower()

        score = 0

        explanations = []

        evidence_tags = []

        # -----------------------------------------------------
        # EXTREME DISCOUNT
        # -----------------------------------------------------

        discount_words = [
            "90% off",
            "95% off",
            "80% off",
            "70% off",
            "free giveaway",
            "free phone",
            "free iphone",
            "free laptop",
            "flash deal",
            "clearance sale",
            "extreme discount",
            "extremely low price",
            "unbelievable price"
        ]

        found_discount = [
            word
            for word in discount_words
            if word in lower
        ]

        if found_discount:

            score += 35

            evidence_tags.append(
                "Extreme Discount"
            )

            explanations.append(
                "The listing contains an unusually "
                "large discount or giveaway."
            )

        # -----------------------------------------------------
        # RISKY PAYMENT
        # -----------------------------------------------------

        payment_words = [
            "gift card",
            "giftcard",
            "zelle",
            "venmo",
            "cashapp",
            "bitcoin",
            "crypto",
            "wire transfer",
            "western union",
            "bank transfer",
            "direct bank transfer",
            "pay before shipping"
        ]

        found_payment = [
            word
            for word in payment_words
            if word in lower
        ]

        if found_payment:

            score += 40

            evidence_tags.append(
                "Irreversible Payment Demand"
            )

            explanations.append(
                "The seller requests a payment method "
                "with limited buyer protection."
            )

        # -----------------------------------------------------
        # SALES PRESSURE
        # -----------------------------------------------------

        pressure_words = [
            "only today",
            "pay now",
            "act now",
            "selling fast",
            "last chance",
            "limited time",
            "first come first serve",
            "only 1 left",
            "only 2 left"
        ]

        found_pressure = [
            word
            for word in pressure_words
            if word in lower
        ]

        if found_pressure:

            score += 25

            evidence_tags.append(
                "High Sales Pressure"
            )

            explanations.append(
                "The listing uses urgency or scarcity "
                "to pressure the buyer."
            )

        # -----------------------------------------------------
        # NO REFUND
        # -----------------------------------------------------

        no_refund = any(
            phrase in lower
            for phrase in [
                "no refund",
                "no refunds",
                "no return",
                "no returns"
            ]
        )

        if no_refund:

            score += 15

            evidence_tags.append(
                "Limited Buyer Protection"
            )

            explanations.append(
                "The listing limits refunds or returns."
            )

        # -----------------------------------------------------
        # COMBINATION RULES
        # -----------------------------------------------------

        if found_discount and found_payment:
            score = max(score, 85)

        if found_discount and found_pressure:
            score = max(score, 75)

        if found_payment and found_pressure:
            score = max(score, 80)

        if found_payment and no_refund:
            score = max(score, 85)

        if (
            found_discount
            and found_payment
            and found_pressure
        ):
            score = 95

        # -----------------------------------------------------
        # NORMAL LISTING
        # -----------------------------------------------------

        if (
            not found_discount
            and not found_payment
            and not found_pressure
            and not no_refund
        ):
            score = 10

        score = min(100, max(0, score))

        risk_level = self.get_risk_level(score)

        if not explanations:

            explanations.append(
                "No major e-commerce scam indicators "
                "were detected."
            )

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "scam_probability": round(
                score / 100,
                2
            ),
            "summary": (
                f"E-Commerce offer assessed as "
                f"{risk_level} with a risk score "
                f"of {score}/100."
            ),
            "explanations": explanations,
            "evidence_tags": (
                evidence_tags
                if evidence_tags
                else ["No Major Indicator"]
            ),
            "recommendations": [
                "Verify seller ratings and independent reviews.",
                "Prefer buyer-protected payment methods.",
                "Avoid direct payments to unknown sellers.",
                "Be careful with extreme discounts and urgency."
            ]
        }

    # =========================================================
    # RISK LEVEL
    # =========================================================

    def get_risk_level(self, score):

        if score <= 25:
            return "SAFE"

        elif score <= 60:
            return "SUSPICIOUS"

        else:
            return "HIGH RISK"

    # =========================================================
    # MESSAGE RECOMMENDATIONS
    # =========================================================

    def get_message_recommendations(self, score):

        if score >= 61:

            return [
                "Do NOT reply to the message.",
                "Do NOT click suspicious links.",
                "Never share OTP, PIN, password, "
                "or banking information.",
                "Verify the request through an official source."
            ]

        elif score >= 26:

            return [
                "Be cautious before responding.",
                "Verify the sender independently.",
                "Do not share sensitive information.",
                "Check the request through the organization's "
                "official website or app."
            ]

        else:

            return [
                "No major threat indicators detected.",
                "Continue normal digital safety practices."
            ]

    # =========================================================
    # URL RECOMMENDATIONS
    # =========================================================

    def get_url_recommendations(
        self,
        score,
        domain
    ):

        if score >= 61:

            return [
                f"Do NOT enter sensitive information on {domain}.",
                "Close the suspicious page.",
                "Use the organization's official website instead."
            ]

        elif score >= 26:

            return [
                "Double-check the domain spelling.",
                "Verify the website independently.",
                "Avoid entering sensitive information until verified."
            ]

        else:

            return [
                "No major URL warning indicators detected.",
                "Still verify the website before entering sensitive information."
            ]


# =============================================================
# COMPLETE SELF TEST
# =============================================================

if __name__ == "__main__":

    model = ScamModel()

    tests = [

        # -----------------------------------------------------
        # MESSAGE - SAFE
        # -----------------------------------------------------

        (
            "message",
            "Your monthly bank statement is available "
            "in your official banking app."
        ),

        # -----------------------------------------------------
        # MESSAGE - SUSPICIOUS
        # -----------------------------------------------------

        (
            "message",
            "Your account needs verification. "
            "Please verify your account information."
        ),

        # -----------------------------------------------------
        # MESSAGE - HIGH RISK
        # -----------------------------------------------------

        (
            "message",
            "URGENT! Your account will be suspended "
            "within 24 hours. Verify your OTP and password "
            "immediately or your account will be locked."
        ),

        # -----------------------------------------------------
        # URL - SAFE
        # -----------------------------------------------------

        (
            "url",
            "https://www.google.com"
        ),

        # -----------------------------------------------------
        # URL - SUSPICIOUS
        # -----------------------------------------------------

        (
            "url",
            "https://example-verification.com/login"
        ),

        # -----------------------------------------------------
        # URL - HIGH RISK
        # -----------------------------------------------------

        (
            "url",
            "http://paypa1-security.xyz/login"
        ),

        # -----------------------------------------------------
        # E-COMMERCE - SAFE
        # -----------------------------------------------------

        (
            "ecommerce",
            "Your order has been shipped successfully. "
            "Track your package using the official app."
        ),

        # -----------------------------------------------------
        # E-COMMERCE - HIGH RISK
        # -----------------------------------------------------

        (
            "ecommerce",
            "Premium smartphone 90% OFF! Only today! "
            "Pay now using gift card. No refunds or returns."
        )
    ]

    print()
    print("=" * 65)
    print("SCAMSHIELD AI COMPLETE SELF TEST")
    print("=" * 65)

    for number, (scan_type, text) in enumerate(
        tests,
        1
    ):

        result = model.analyze(
            scan_type,
            text
        )

        print()
        print(
            f"TEST {number} - {scan_type.upper()}"
        )

        print(
            "Input:",
            text
        )

        print(
            "Risk Score:",
            result["risk_score"]
        )

        print(
            "Risk Level:",
            result["risk_level"]
        )

        print(
            "Evidence:",
            ", ".join(
                result["evidence_tags"]
            )
        )

    print()
    print("=" * 65)
    print("SELF TEST COMPLETE")
    print("=" * 65)