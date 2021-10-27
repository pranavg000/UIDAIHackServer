from django.http.response import JsonResponse
from django.shortcuts import render
from rest_framework.parsers import JSONParser
from rest_framework.decorators import api_view
from django.http import JsonResponse
from .models import *
from .decorators import check_token, request_interface
import string
import random
from pyfcm import FCMNotification

push_notification_service = FCMNotification(api_key="<api-key>")

AUTH_TOKEN_LEN = 16
SHAREABLE_CODE_LEN = 9


@api_view(['POST'])
@request_interface(['uidToken', 'deviceID', 'publicKey'])
def auth(request):
    if request.method == 'POST':
        # data = JSONParser.parse(request)
        uidToken = request.data['uidToken']
        deviceID = request.data['deviceID']
        publicKey = request.data['publicKey']

        #TODO: OTP API (AN) 
            

        if AnonProfile.objects.filter(uidToken=uidToken).exists():

            profile = AnonProfile.objects.get(uidToken=uidToken)
            profile.uidToken = uidToken
            profile.deviceID = deviceID
            profile.publicKey = publicKey
            profile.save()

            return JsonResponse({'shareableCode': profile.shareableCode}, status=200)

        shareableCode = genShareableCode()
        authToken = genAuthToken()

        AnonProfile.objects.create(uidToken=uidToken, authToken=authToken, deviceID=deviceID, publicKey=publicKey, shareableCode=shareableCode)

        return JsonResponse({'shareableCode': shareableCode, 'authToken': authToken}, status=200)
    return JsonResponse({}, status=400)

@api_view(['POST'])
@check_token
@request_interface(['receiverSC', 'message'])
def sendrequest(request):
    if request.method == 'POST':
        if AnonProfile.objects.filter(shareableCode=request.data['receiverSC']).exists():
            pass
    return JsonResponse({}, status=400)

def sendPushNotification(deviceID, messageTitle, messageBody, dataMessage=None):
    result = push_notification_service.notify_single_device(registration_id=deviceID, message_title=messageTitle, message_body=messageBody, data_message=dataMessage)
    if result['success'] == 1:
        return True
    return False


def genAuthToken():
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(AUTH_TOKEN_LEN))

def genShareableCode():
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(SHAREABLE_CODE_LEN))