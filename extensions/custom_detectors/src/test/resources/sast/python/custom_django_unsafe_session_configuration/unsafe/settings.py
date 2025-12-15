# -*- coding: utf-8 -*-

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
]

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)

SESSION_COOKIE_AGE = 3600 # FLAW
SESSION_COOKIE_DOMAIN = '.com' # FLAW
SESSION_COOKIE_PATH = "/" # FLAW
SESSION_COOKIE_HTTPONLY = False # FLAW
SESSION_COOKIE_SECURE = False # FLAW
SESSION_COOKIE_SAMESITE = "Lax" # FLAW
