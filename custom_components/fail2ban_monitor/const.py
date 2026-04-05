"""Constantes pour Fail2ban Monitor."""

DOMAIN = "fail2ban_monitor"

CONF_HOST = "host"
CONF_PORT = "port"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_USE_SUDO = "use_sudo"

# Authentification SSH
CONF_AUTH_METHOD = "auth_method"
CONF_PRIVATE_KEY = "private_key"
CONF_KEY_PASSPHRASE = "key_passphrase"

AUTH_METHOD_PASSWORD = "password"
AUTH_METHOD_KEY = "private_key"

DEFAULT_PORT = 22
DEFAULT_SCAN_INTERVAL = 60  # secondes
DEFAULT_USE_SUDO = True

PLATFORMS = ["sensor", "binary_sensor"]
