# # Licensed to the Apache Software Foundation (ASF) under one
# # or more contributor license agreements.  See the NOTICE file
# # distributed with this work for additional information
# # regarding copyright ownership.  The ASF licenses this file
# # to you under the Apache License, Version 2.0 (the
# # "License"); you may not use this file except in compliance
# # with the License.  You may obtain a copy of the License at
# #
# #   http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing,
# # software distributed under the License is distributed on an
# # "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# # KIND, either express or implied.  See the License for the
# # specific language governing permissions and limitations
# # under the License.
# #
# # This file is included in the final Docker image and SHOULD be overridden when
# # deploying the image to prod. Settings configured here are intended for use in local
# # development environments. Also note that superset_config_docker.py is imported
# # as a final step as a means to override "defaults" configured here
# #
# import logging
# import os
# import sys

# from celery.schedules import crontab
# from flask_caching.backends.filesystemcache import FileSystemCache

# logger = logging.getLogger()

# DATABASE_DIALECT = os.getenv("DATABASE_DIALECT")
# DATABASE_USER = os.getenv("DATABASE_USER")
# DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
# DATABASE_HOST = os.getenv("DATABASE_HOST")
# DATABASE_PORT = os.getenv("DATABASE_PORT")
# DATABASE_DB = os.getenv("DATABASE_DB")

# EXAMPLES_USER = os.getenv("EXAMPLES_USER")
# EXAMPLES_PASSWORD = os.getenv("EXAMPLES_PASSWORD")
# EXAMPLES_HOST = os.getenv("EXAMPLES_HOST")
# EXAMPLES_PORT = os.getenv("EXAMPLES_PORT")
# EXAMPLES_DB = os.getenv("EXAMPLES_DB")

# # The SQLAlchemy connection string.
# SQLALCHEMY_DATABASE_URI = (
#     f"{DATABASE_DIALECT}://"
#     f"{DATABASE_USER}:{DATABASE_PASSWORD}@"
#     f"{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}"
# )

# SQLALCHEMY_EXAMPLES_URI = (
#     f"{DATABASE_DIALECT}://"
#     f"{EXAMPLES_USER}:{EXAMPLES_PASSWORD}@"
#     f"{EXAMPLES_HOST}:{EXAMPLES_PORT}/{EXAMPLES_DB}"
# )

# REDIS_HOST = os.getenv("REDIS_HOST", "redis")
# REDIS_PORT = os.getenv("REDIS_PORT", "6379")
# REDIS_CELERY_DB = os.getenv("REDIS_CELERY_DB", "0")
# REDIS_RESULTS_DB = os.getenv("REDIS_RESULTS_DB", "1")

# RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")

# CACHE_CONFIG = {
#     "CACHE_TYPE": "RedisCache",
#     "CACHE_DEFAULT_TIMEOUT": 300,
#     "CACHE_KEY_PREFIX": "superset_",
#     "CACHE_REDIS_HOST": REDIS_HOST,
#     "CACHE_REDIS_PORT": REDIS_PORT,
#     "CACHE_REDIS_DB": REDIS_RESULTS_DB,
# }
# DATA_CACHE_CONFIG = CACHE_CONFIG
# THUMBNAIL_CACHE_CONFIG = CACHE_CONFIG


# class CeleryConfig:
#     broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
#     imports = (
#         "superset.sql_lab",
#         "superset.tasks.scheduler",
#         "superset.tasks.thumbnails",
#         "superset.tasks.cache",
#     )
#     result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
#     worker_prefetch_multiplier = 1
#     task_acks_late = False
#     beat_schedule = {
#         "reports.scheduler": {
#             "task": "reports.scheduler",
#             "schedule": crontab(minute="*", hour="*"),
#         },
#         "reports.prune_log": {
#             "task": "reports.prune_log",
#             "schedule": crontab(minute=10, hour=0),
#         },
#     }


# CELERY_CONFIG = CeleryConfig

# FEATURE_FLAGS = {"ALERT_REPORTS": True}
# ALERT_REPORTS_NOTIFICATION_DRY_RUN = True
# WEBDRIVER_BASEURL = f"http://superset_app{os.environ.get('SUPERSET_APP_ROOT', '/')}/"  # When using docker compose baseurl should be http://superset_nginx{ENV{BASEPATH}}/  # noqa: E501
# # The base URL for the email report hyperlinks.
# WEBDRIVER_BASEURL_USER_FRIENDLY = (
#     f"http://localhost:8888/{os.environ.get('SUPERSET_APP_ROOT', '/')}/"
# )
# SQLLAB_CTAS_NO_LIMIT = True

# log_level_text = os.getenv("SUPERSET_LOG_LEVEL", "INFO")
# LOG_LEVEL = getattr(logging, log_level_text.upper(), logging.INFO)

# if os.getenv("CYPRESS_CONFIG") == "true":
#     # When running the service as a cypress backend, we need to import the config
#     # located @ tests/integration_tests/superset_test_config.py
#     base_dir = os.path.dirname(__file__)
#     module_folder = os.path.abspath(
#         os.path.join(base_dir, "../../tests/integration_tests/")
#     )
#     sys.path.insert(0, module_folder)
#     from superset_test_config import *  # noqa

#     sys.path.pop(0)

# #
# # Optionally import superset_config_docker.py (which will have been included on
# # the PYTHONPATH) in order to allow for local settings to be overridden
# #
# try:
#     import superset_config_docker
#     from superset_config_docker import *  # noqa

#     logger.info(
#         f"Loaded your Docker configuration at [{superset_config_docker.__file__}]"
#     )
# except ImportError:
#     logger.info("Using default Docker config...")

import logging
from flask_appbuilder.security.manager import AUTH_OAUTH
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import AuthOAuthView
from flask_login import login_user
import jwt
import requests
from flask_appbuilder.views import expose
from flask import request, redirect, g
from jwt.algorithms import RSAAlgorithm
import json

logger = logging.getLogger(__name__)

class CustomAuthOAuthView(AuthOAuthView):
    def get_public_key(self,jwks_url, kid):
        """Fetch the public key from JWKS and convert it to PEM format."""
        logger.info(f"Token jwks: {jwks_url}")
        jwks = requests.get(jwks_url).json()  # Fetch JWKS JSON
        for key in jwks.get("keys", []):
            if key["kid"] == kid:  # Match the correct key ID (kid)
                return RSAAlgorithm.from_jwk(json.dumps(key))  # Convert to PEM format
        raise Exception("Public key not found in JWKS")


    @expose("/login/")
    def login(self):
        logger.info("Custom login method called")
        token = request.args.get('token')
        if token:
            logger.info(f"Token received: {token[:20]}...")
            try:
                # Verify token with Keycloak
                if not hasattr(g, 'appbuilder') or not g.appbuilder:
                    from flask import current_app
                    g.appbuilder = current_app.appbuilder
                sm = g.appbuilder.sm
                logger.info(f"Token received: {sm}")
                metadata = sm.oauth_remotes['keycloak'].server_metadata
                jwks_url = metadata.get('jwks_uri')
                jwks = requests.get(jwks_url).json()
                headers = jwt.get_unverified_header(token)  # Extract header info
                logger.info(f"Token received: {headers}")
                kid = headers.get("kid")
                logger.info(f"Token received: {kid}")
                public_key = self.get_public_key(jwks_url, kid)  # Convert JWKS to PEM
                logger.info(f"Token received: {public_key}")
        
                # ✅ Correct way to decode the JWT using PEM key
                parsed_token = jwt.decode(
                    token,
                    public_key,  # Use extracted and formatted PEM key
                    algorithms=["RS256"],
                    audience="account",
                    options={"verify_exp": True}
                )
                logger.info(f"Token received: {parsed_token}...")
                # Extract user info and handle registration/login
                username = parsed_token.get('preferred_username')
                user = sm.find_user(username=username)
                logger.info(f"Token received: {username}...")
                if not user and AUTH_USER_REGISTRATION:
                    user = sm.add_user(
                        username=username,
                        first_name=parsed_token.get('given_name', ''),
                        last_name=parsed_token.get('family_name', ''),
                        email=parsed_token.get('email'),
                        role=sm.find_role(AUTH_USER_REGISTRATION_ROLE)
                    )
                login_user(user, remember=False)
                logger.info(f"Token received: {user}...")
                return redirect(request.args.get('redirect', '/'))
            except Exception as e:
                logger.error(f"Token login failed: {e}")
        return super().login()

# Database configuration
# SQLALCHEMY_DATABASE_URI = 'postgresql://superset:superset@db:5432/superset'
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = 'f3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3'

AUTH_TYPE = AUTH_OAUTH
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Admin"

class CustomSSOSecurityManager(SupersetSecurityManager):
    authoauthview = CustomAuthOAuthView

    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        self.authoauthview = CustomAuthOAuthView
        # self.init_oauth()


    def init_oauth(self):
        self.oauth_remotes.pop('keycloak')
        self.oauth_remotes['keycloak'] = self.create_oauth_remote(
            'keycloak',
            server_metadata_url='http://192.168.30.39:8083/realms/metabaserealm/.well-known/openid-configuration',
            client_id='metabase',
            client_secret='ildWQrkMkNfuCzWXuOlgurGwx49pI18X',
            api_base_url='http://192.168.30395:8083/realms/metabaserealm/protocol/openid-connect',
            client_kwargs={
                'scope': 'openid email profile',
            }
        )


# OAuth configuration
CUSTOM_SECURITY_MANAGER = CustomSSOSecurityManager



OAUTH_PROVIDERS = [
    {
        "name": "keycloak",
        "token_key": "access_token",
        "icon": "fa-key",
        'remote_app': {
            'server_metadata_url': 'http://192.168.30.39:8083/realms/metabaserealm/.well-known/openid-configuration',
            "client_id": "metabase",
            "client_secret": "ildWQrkMkNfuCzWXuOlgurGwx49pI18X",
            "api_base_url": "http://192.168.30.39:8083/realms/metabaserealm/protocol/openid-connect",
            "client_kwargs": {
                "scope": "openid email profile",
            },
            "access_token_url": "http://192.168.30.39:8083/realms/metabaserealm/protocol/openid-connect/token",
            "authorize_url": "http://192.168.30.39:8083/realms/metabaserealm/protocol/openid-connect/auth",
            "userinfo_endpoint": "http://192.168.30.39:8083/realms/metabaserealm/protocol/openid-connect/userinfo",
            "jwks_uri": "http://192.168.30.39:8083/realms/metabaserealm/protocol/openid-connect/certs",
        },
    }
]

logger.info("Custom Superset configuration loaded successfully!")