import requests
import json
from datetime import datetime


class SIEMClient:
    def __init__(self, base_url="http://localhost:4567"):
        self.base_url = base_url

    def send_login_attempt(self, user_id, success, ip_address, details=None):
        """Envia um log de tentativa de login para o SIEM"""
        log_data = {
            "event_type": "login_success" if success else "login_failed",
            "severity": "low" if success else "medium",
            "message": f"{'Successful' if success else 'Failed'} login attempt for user {user_id}",
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "ip_address": ip_address,
            "details": details or {},
        }
        return self._send_log(log_data)

    def send_transaction(
        self, user_id, amount, transaction_type, ip_address, details=None
    ):
        """Envia um log de transação para o SIEM"""
        log_data = {
            "event_type": "transaction",
            "severity": "low" if amount < 10000 else "medium",
            "message": f"Transaction of {amount} {transaction_type} for user {user_id}",
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "ip_address": ip_address,
            "details": {"amount": amount, "type": transaction_type, **(details or {})},
        }
        return self._send_log(log_data)

    def send_account_access(self, user_id, ip_address, details=None):
        """Envia um log de acesso à conta para o SIEM"""
        log_data = {
            "event_type": "account_access",
            "severity": "low",
            "message": f"Account access for user {user_id}",
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "ip_address": ip_address,
            "details": details or {},
        }
        return self._send_log(log_data)

    def _send_log(self, log_data):
        """Envia um log genérico para o SIEM"""
        response = requests.post(
            f"{self.base_url}/logs",
            json=log_data,
            headers={"Content-Type": "application/json"},
        )
        return response.json()


# Exemplo de uso
if __name__ == "__main__":
    siem = SIEMClient()

    # Exemplo de tentativa de login
    print("Sending login attempt...")
    response = siem.send_login_attempt(
        user_id="user123",
        success=True,
        ip_address="192.168.1.1",
        details={"browser": "Chrome", "os": "Windows"},
    )
    print(f"Response: {response}")

    # Exemplo de transação
    print("\nSending transaction...")
    response = siem.send_transaction(
        user_id="user123",
        amount=15000,
        transaction_type="transfer",
        ip_address="192.168.1.1",
        details={"recipient": "user456", "currency": "USD"},
    )
    print(f"Response: {response}")

    # Exemplo de acesso à conta
    print("\nSending account access...")
    response = siem.send_account_access(
        user_id="user123", ip_address="192.168.1.1", details={"action": "view_balance"}
    )
    print(f"Response: {response}")
