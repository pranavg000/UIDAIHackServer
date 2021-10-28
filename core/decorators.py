from functools import wraps
from json.encoder import JSONEncoder
from django.http import HttpResponseRedirect
from django.http.response import JsonResponse
from .models import AnonProfile

def check_token(func):
    print(func, "####################################")
    def decorator(func):
        print(func, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        @request_interface(['uidToken', 'authToken'])
        def wrap(request, *args, **kwargs):
            if AnonProfile.objects.filter(uidToken=request.data['uidToken'], authToken=request.data['authToken']).exists():
                return func(request, *args, **kwargs)
            return JsonResponse({}, status=401)
        return wrap
    return decorator

def request_interface(keyList):
    def decorator(func):
        def wrap(request, *args, **kwargs):
            for key in keyList:
                if key not in request.data:
                    return JsonResponse({"KeyNotFound": key}, status=400)
            return func(request, *args, **kwargs)
        return wrap
    return decorator