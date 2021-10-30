from functools import wraps
from json.encoder import JSONEncoder
from django.http import HttpResponseRedirect
from django.http.response import JsonResponse
from .models import AnonProfile
import logging

genLogger = logging.getLogger('django.server')

def check_token(func):
    @request_interface(['uidToken', 'authToken'])
    def wrap(request, *args, **kwargs):
        if AnonProfile.objects.filter(uidToken=request.data['uidToken'], authToken=request.data['authToken']).exists():
            return func(request, *args, **kwargs)
        genLogger.warning(f"{request.data['uidToken']}:Invalid auth token")
        return JsonResponse({"message": "Invalid authToken"}, status=401)
    wrap.__doc__ = func.__doc__
    wrap.__name__ = func.__name__
    return wrap

def request_interface(keyList):
    def decorator(func):
        def wrap(request, *args, **kwargs):
            for key in keyList:
                if key not in request.data:
                    genLogger.warning(f"KeyNotFound: {key}")
                    return JsonResponse({"message": f"KeyNotFound: {key}"}, status=400)
            return func(request, *args, **kwargs)
        return wrap
    return decorator