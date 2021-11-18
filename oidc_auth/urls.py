from django.urls import re_path
from .views import login_begin, login_complete

urlpatterns = [
    re_path(r'^login/$', login_begin, name='oidc-login'),
    re_path(r'^complete/$', login_complete, name='oidc-complete'),
]
