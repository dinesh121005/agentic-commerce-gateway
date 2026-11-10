from app.policy.mandate import Mandate
from app.policy.requests import PolicyDecision, PolicyOutcome, PurchaseRequest, RuleViolated


def evaluate(
    purchase_request: PurchaseRequest,
    mandate: Mandate,
    current_daily_spend: float = 0.0,
) -> PolicyDecision:
    """
    Pure, deterministic evaluation function that checks a proposed purchase request against a customer's mandate.

    Rules are evaluated in strict fail-fast sequential order (Doc 07 §8):
      1. customer_id match -> AUTH_CUSTOMER_MISMATCH (CUSTOMER_MISMATCH)
      2. mandate.is_expired() is False -> MANDATE_EXPIRED
      3. merchant in allowed_merchants (case-insensitive, trimmed, '*' wildcard supported) -> MERCHANT_UNAUTHORIZED
      4. category in allowed_categories (case-insensitive, trimmed, '*' wildcard supported) -> CATEGORY_UNAUTHORIZED
      5. amount <= max_transaction_amount (inclusive boundary) -> AMOUNT_EXCEEDS_TRANSACTION_LIMIT
      6. (current_daily_spend + amount) <= daily_limit -> DAILY_BUDGET_EXCEEDED
      7. Threshold safety evaluation:
         - amount >= ₹500.00 (50,000 paise) -> STEP_UP
         - amount < ₹500.00 (50,000 paise) -> ALLOW

    DENY is terminal and absolute: if any rule is violated, returns PolicyOutcome.DENY immediately.
    """
    # 1. Customer ID match
    if purchase_request.customer_id != mandate.customer_id:
        return PolicyDecision(
            status="REJECTED",
            decision=PolicyOutcome.DENY,
            reason=f"Customer ID '{purchase_request.customer_id}' does not match mandate customer '{mandate.customer_id}'",
            rule_violated=RuleViolated.CUSTOMER_MISMATCH,
            reason_code="AUTH_CUSTOMER_MISMATCH",
        )

    # 2. Mandate expiry check
    if mandate.is_expired():
        expiry_str = mandate.expires_at.isoformat() if mandate.expires_at else "unknown"
        return PolicyDecision(
            status="REJECTED",
            decision=PolicyOutcome.DENY,
            reason=f"Mandate for customer '{mandate.customer_id}' has expired (expired at {expiry_str})",
            rule_violated=RuleViolated.MANDATE_EXPIRED,
            reason_code="MANDATE_EXPIRED",
        )

    # 3. Merchant authorization check (case-insensitive, trimmed)
    allowed_merchants_normalized = [m.strip().lower() for m in mandate.allowed_merchants]
    if "*" not in allowed_merchants_normalized and purchase_request.merchant.strip().lower() not in allowed_merchants_normalized:
        return PolicyDecision(
            status="REJECTED",
            decision=PolicyOutcome.DENY,
            reason=f"Merchant '{purchase_request.merchant}' is not authorized in customer mandate (allowed: {mandate.allowed_merchants})",
            rule_violated=RuleViolated.MERCHANT_NOT_ALLOWED,
            reason_code="MERCHANT_UNAUTHORIZED",
        )

    # 4. Category authorization check (case-insensitive, trimmed)
    allowed_categories_normalized = [c.strip().lower() for c in mandate.allowed_categories]
    if "*" not in allowed_categories_normalized and purchase_request.category.strip().lower() not in allowed_categories_normalized:
        return PolicyDecision(
            status="REJECTED",
            decision=PolicyOutcome.DENY,
            reason=f"Product category '{purchase_request.category}' is not authorized in customer mandate (allowed: {mandate.allowed_categories})",
            rule_violated=RuleViolated.CATEGORY_NOT_ALLOWED,
            reason_code="CATEGORY_UNAUTHORIZED",
        )

    # 5. Transaction amount boundary check (inclusive)
    if purchase_request.amount > mandate.max_transaction_amount:
        return PolicyDecision(
            status="REJECTED",
            decision=PolicyOutcome.DENY,
            reason=(
                f"Transaction amount ₹{purchase_request.amount:.2f} exceeds "
                f"maximum mandate limit of ₹{mandate.max_transaction_amount:.2f}"
            ),
            rule_violated=RuleViolated.AMOUNT_EXCEEDS_LIMIT,
            reason_code="AMOUNT_EXCEEDS_TRANSACTION_LIMIT",
        )

    # 6. Cumulative Daily Spend Boundary Check
    if mandate.daily_limit is not None and (current_daily_spend + purchase_request.amount) > mandate.daily_limit:
        projected_spend = current_daily_spend + purchase_request.amount
        return PolicyDecision(
            status="REJECTED",
            decision=PolicyOutcome.DENY,
            reason=(
                f"Transaction amount ₹{purchase_request.amount:.2f} would take today's spend to "
                f"₹{projected_spend:.2f}, exceeding the ₹{mandate.daily_limit:.2f} daily mandate cap "
                f"(current spend today: ₹{current_daily_spend:.2f})"
            ),
            rule_violated=RuleViolated.DAILY_LIMIT_EXCEEDED,
            reason_code="DAILY_BUDGET_EXCEEDED",
        )

    # 7. Exact threshold safety evaluation (>= 50,000 paise / ₹500.00 -> STEP_UP, < 50,000 paise -> ALLOW)
    req_paise = purchase_request.amount_paise if purchase_request.amount_paise is not None else int(round(purchase_request.amount * 100))
    if req_paise >= 50000:
        return PolicyDecision(
            status="APPROVED",
            decision=PolicyOutcome.STEP_UP,
            reason=(
                f"Transaction amount ₹{purchase_request.amount:.2f} is within mandate limit of "
                f"₹{mandate.max_transaction_amount:.2f} and meets all policy criteria. "
                f"Requires customer confirmation (amount >= ₹500.00)."
            ),
            rule_violated=None,
            reason_code="STEP_UP_REQUIRED",
        )

    return PolicyDecision(
        status="APPROVED",
        decision=PolicyOutcome.ALLOW,
        reason=(
            f"Transaction amount ₹{purchase_request.amount:.2f} is within "
            f"mandate limit of ₹{mandate.max_transaction_amount:.2f} and meets all policy criteria"
        ),
        rule_violated=None,
        reason_code="POLICY_APPROVED",
    )

