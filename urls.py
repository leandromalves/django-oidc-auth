from django.urls import include, re_path
from django.contrib import admin

from views import index

admin.autodiscover()


urlpatterns = [
    re_path(r'^$', index),
    re_path(r'^oidc/', include('oidc_auth.urls')),
    re_path(r'^admin/', admin.site.urls),
]
