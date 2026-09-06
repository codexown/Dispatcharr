from django.test import TestCase
from rest_framework.test import APIClient

from apps.accounts.models import User


class AccessSentinelTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(username="admin", password="test")
        self.admin.user_level = 10
        self.admin.save(update_fields=["user_level"])
        self.user = User.objects.create_user(username="streamer", password="test")
        self.client = APIClient()
        self.client.force_authenticate(self.admin)
        self.url = f"/api/accounts/users/{self.user.id}/access-sentinel/"

    def test_suspend_preserves_all_unowned_properties(self):
        self.user.custom_properties = {
            "xc_password": "unchanged",
            "dvr_access": "view",
            "allowed_networks": {"XC": "10.0.0.0/8"},
        }
        self.user.save(update_fields=["custom_properties"])

        response = self.client.patch(self.url, {"suspended": True}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"id": self.user.id, "username": "streamer", "sentinel_present": True})
        self.user.refresh_from_db()
        self.assertEqual(
            self.user.custom_properties,
            {
                "xc_password": "unchanged",
                "dvr_access": "view",
                "allowed_networks": {"XC": "10.0.0.0/8", "M3U_EPG": "127.0.0.1/32"},
            },
        )

    def test_restore_removes_only_sentinel_scope(self):
        self.user.custom_properties = {"allowed_networks": {"M3U_EPG": "127.0.0.1/32", "XC": "10.0.0.0/8"}}
        self.user.save(update_fields=["custom_properties"])

        response = self.client.patch(self.url, {"suspended": False}, format="json")

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.custom_properties, {"allowed_networks": {"XC": "10.0.0.0/8"}})

    def test_rejects_non_boolean_and_malformed_networks(self):
        self.assertEqual(self.client.patch(self.url, {"suspended": "true"}, format="json").status_code, 400)
        self.user.custom_properties = {"allowed_networks": {"M3U_EPG": "invalid"}}
        self.user.save(update_fields=["custom_properties"])
        self.assertEqual(self.client.patch(self.url, {"suspended": True}, format="json").status_code, 400)
