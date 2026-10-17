"""Conversation state identifiers used by ``python-telegram-bot``'s
``ConversationHandler``.  Centralised here so the same integer is
never duplicated across modules.
"""
from enum import IntEnum


class State(IntEnum):
    # Generic
    MAIN_MENU = 0

    # Deposit flow
    DEPOSIT_SELECT_CURRENCY = 10
    DEPOSIT_ENTER_AMOUNT = 11
    DEPOSIT_UPLOAD_RECEIPT = 12
    DEPOSIT_ENTER_TX_HASH = 13
    DEPOSIT_CONFIRM = 14

    # Investment flow
    INVEST_SELECT_PLAN = 20
    INVEST_ENTER_AMOUNT = 21
    INVEST_CONFIRM = 22

    # Withdrawal flow
    WITHDRAW_ENTER_AMOUNT = 30
    WITHDRAW_SELECT_METHOD = 31   # GCash / Maya / Crypto picker
    WITHDRAW_ENTER_ADDRESS = 33   # crypto address (kept for crypto path)
    WITHDRAW_CONFIRM = 32

    # Admin flows
    ADMIN_PLAN_NAME = 100
    ADMIN_PLAN_DESCRIPTION = 101
    ADMIN_PLAN_MIN = 102
    ADMIN_PLAN_MAX = 103
    ADMIN_PLAN_DAILY_ROI = 104
    ADMIN_PLAN_DURATION = 105
    ADMIN_PLAN_SORT = 106
    ADMIN_PLAN_TOGGLE = 107

    ADMIN_EDIT_SETTING = 110
    ADMIN_BROADCAST = 120
    ADMIN_USER_LOOKUP = 130
    ADMIN_ADJUST_BALANCE = 131
    ADMIN_ADJUST_NOTE = 132


# Callback data prefixes (used to route callback_query updates)
CB = {
    "main_menu": "M:0",
    "deposit": "D:0",
    "deposit_currency": "D:C:",  # D:C:BTC
    "invest": "I:0",
    "invest_plan": "I:P:",  # I:P:3
    "withdraw": "W:0",
    "withdraw_method": "W:M:",  # W:M:GCASH | W:M:MAYA | W:M:CRYPTO
    "referral": "R:0",
    "history": "H:0",
    "my_investments": "MI:0",
    "admin_home": "A:0",
    "admin_plans": "A:P",
    "admin_plan_new": "A:PN",
    "admin_plan_toggle": "A:PT:",  # A:PT:3
    "admin_plan_delete": "A:PD:",  # A:PD:3
    "admin_deposits": "A:D",
    "admin_deposit_approve": "A:DA:",  # A:DA:55
    "admin_deposit_reject": "A:DR:",  # A:DR:55
    "admin_withdrawals": "A:W",
    "admin_withdrawal_approve": "A:WA:",  # A:WA:55
    "admin_withdrawal_reject": "A:WR:",  # A:WR:55
    "admin_users": "A:U",
    "admin_user_view": "A:UV:",  # A:UV:123456
    "admin_user_ban": "A:UB:",  # A:UB:123456
    "admin_user_unban": "A:UU:",  # A:UU:123456
    "admin_user_adjust": "A:UA:",  # A:UA:123456
    "admin_settings": "A:S",
    "admin_setting_edit": "A:SE:",  # A:SE:referral_bonus_percent
    "admin_broadcast": "A:B",
    "admin_stats": "A:ST",
    "admin_cancel": "A:X",
    "noop": "NOOP",
}
