from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def change_email(request):
    request.user.email = request.POST["email"]
    request.user.save()
    return JsonResponse({"ok": True})
