from django.conf.urls import url
from .views import login_begin, login_complete

urlpatterns = [
    url(r'^login/$', login_begin, name='oidc-login'),
    url(r'^complete/$', login_complete, name='oidc-complete'),
]
