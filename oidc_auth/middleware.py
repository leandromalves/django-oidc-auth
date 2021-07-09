from models import OpenIdUser

class OpenIDAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # before view

        if request.user.is_authenticated:
            oidc_user = OpenIdUser.objects.get(user=request.user)

            # verificar se está autenticado
            oidc_user = 


        response = self.get_response(request)
        return response