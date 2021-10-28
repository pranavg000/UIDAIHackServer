from django.http.response import JsonResponse
from django.shortcuts import render
from rest_framework.parsers import JSONParser
from rest_framework.decorators import api_view
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import *
from .decorators import check_token, request_interface
import string
import random
from pyfcm import FCMNotification
from django.conf import settings
from django.core.files.storage import default_storage

push_notification_service = FCMNotification(api_key=settings.FIREBASE_SERVER_KEY)

AUTH_TOKEN_LEN = 16
SHAREABLE_CODE_LEN = 9


@api_view(['POST'])
@request_interface(['uid'])
def authUID(request):
    if request.method == 'POST':
        # data = JSONParser.parse(request)
        
        transactionNo = callOTPAPI(request.data['uid'])
        
        return JsonResponse({'transactionNo': transactionNo}, status=200)
    return JsonResponse({}, status=400)

def callOTPAPI(uid):
    #TODO: OTP API (AN) 
    transactionNo = ""
    while(transactionNo=="" or OTPAPISim.objects.filter(transactionNo=transactionNo).exists()):
        transactionNo = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
    
    
    if OTPAPISim.objects.filter(uid=uid).exists():
        banda = OTPAPISim.objects.get(uid=uid)
        banda.transactionNo = transactionNo
        banda.save()
        return transactionNo
    
    uidToken = ""
    while(uidToken=="" or OTPAPISim.objects.filter(uidToken=uidToken).exists()):
        uidToken = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))

    OTPAPISim.objects.create(uid=uid, transactionNo=transactionNo, uidToken=uidToken)

    return transactionNo

@api_view(['POST'])
@request_interface(['transactionNo', 'otp', 'deviceID', 'publicKey'])
def authOTP(request):
    if request.method == 'POST':
        # data = JSONParser.parse(request)
        
        result, uidToken = verifyOTPAuthAPI(request.data['transactionNo'], request.data['otp'])
        
        if not result:
            return JsonResponse({}, status=403)

        deviceID = request.data['deviceID']
        publicKey = request.data['publicKey']

        if AnonProfile.objects.filter(uidToken=uidToken).exists():
            profile = AnonProfile.objects.get(uidToken=uidToken)
            profile.publicKey = publicKey
            profile.deviceID = deviceID
            profile.save()

            return JsonResponse({'shareableCode': profile.shareableCode, 'authToken': profile.authToken, 'uidToken': uidToken}, status=200)

        shareableCode = genShareableCode()
        authToken = genAuthToken()

        AnonProfile.objects.create(uidToken=uidToken, authToken=authToken, deviceID=deviceID, publicKey=publicKey, shareableCode=shareableCode)
        return JsonResponse({'shareableCode': shareableCode, 'authToken': authToken, 'uidToken': uidToken}, status=200)

    return JsonResponse({}, status=403)


def verifyOTPAuthAPI(transactionNo, otp):
    if otp == '12345':
        if OTPAPISim.objects.filter(transactionNo=transactionNo).exists():
            uidToken = OTPAPISim.objects.get(transactionNo=transactionNo).uidToken
            return True, uidToken
    return False, None


# @api_view(['POST'])
# @check_token
# @request_interface(['uidToken', 'deviceID', 'publicKey'])
# def authFinal(request):
#     if request.method == 'POST':
#         # data = JSONParser.parse(request)
#         uidToken = request.data['uidToken']
#         deviceID = request.data['deviceID']
#         publicKey = request.data['publicKey']

#         if AnonProfile.objects.filter(uidToken=uidToken).exists():

#             profile = AnonProfile.objects.get(uidToken=uidToken)
#             profile.deviceID = deviceID
#             profile.publicKey = publicKey
#             profile.save()

#             return JsonResponse({}, status=200)

#     return JsonResponse({}, status=400)

@api_view(['POST'])
@check_token
@request_interface(['receiverSC', 'message'])
def sendRequest(request):
    if request.method == 'POST':
        try:
            lender = AnonProfile.objects.get(shareableCode=request.data['receiverSC'])
            requester = AnonProfile.objects.filter(uidToken=request.data['uidToken']).exists()
            Transaction.objects.filter(lender=lender, requester=requester).update(status='aborted')
            Transaction.objects.add(lender=lender, requester=requester)
            if sendPushNotification(lender.deviceID, "New Address Request", request.data['message']):
                return JsonResponse({'body': 'message sent'}, status=200)
            else:
                return JsonResponse({'body': 'Unable to send message'}, status=400)
        except:
            return JsonResponse({}, status=400)

    return JsonResponse({}, status=400)



def sendPushNotification(deviceID, messageTitle, messageBody, dataMessage=None):
    return
    result = push_notification_service.notify_single_device(registration_id=deviceID, message_title=messageTitle, message_body=messageBody, data_message=dataMessage)
    if result['success'] == 1:
        return True

    return False        # Pray that this never happens


def genAuthToken():
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(AUTH_TOKEN_LEN))

def genShareableCode():
    shareableCode = ""
    while (shareableCode == "" or AnonProfile.objects.filter(shareableCode=shareableCode).exists()):
        shareableCode = ''.join(random.choice(string.ascii_uppercase) for _ in range(SHAREABLE_CODE_LEN))
    return shareableCode


@api_view(['POST'])
@request_interface(['txnID', 'eKYC', 'passcode', 'filename'])
def POSTekyc(request):
    if request.method == 'POST':
        try:
            transactionId = request.data['txnID']
            eKYC_enc = request.data['eKYC']
            passcode_enc = request.data['passcode']
            filename = request.data['filename']

            print(transactionId, eKYC_enc, passcode_enc, filename)
            renterDeviceId = Transaction.objects.get(id=transactionId).requester.deviceID
            print(transactionId, eKYC_enc, passcode_enc, filename, renterDeviceId)

            OfflineEKYC.objects.create(
                transactionId=transactionId,
                encryptedEKYC=eKYC_enc,
                encryptedPasscode=passcode_enc,
                filename=filename,
            )
            print(transactionId, eKYC_enc, passcode_enc, filename)

            message_caption = "Address Request Approved!"
            message_body = "Hi There! Landlord has approved your request to share his address, please click the button to get the address"
            
            if sendPushNotification(renterDeviceId, message_caption, message_body):
                return JsonResponse({'body': {
                    'message':'Hello from the server!', 
                    'txnID': transactionId
                    }}, status=200)
            return JsonResponse({'body': 'Push Notification Failure'}, status=500)
        except:
            return JsonResponse({'body': 'POST request failed, please request again'}, status=500)

    return JsonResponse({'body': 'Please "POST" the request'}, status=400)


@api_view(['GET'])
@request_interface(['txnID'])
def GETekyc(request):
    if request.method == 'GET':
        try:
            transactionId = request.data['txnID']
            offlineEKYC = OfflineEKYC.objects.get(transactionId=transactionId)
            return JsonResponse({
                'body': {
                    'encryptedEKYC': offlineEKYC.encryptedEKYC,
                    'encryptedPasscode': offlineEKYC.encryptedPasscode,
                    'filename': offlineEKYC.filename,
                    'txnID': offlineEKYC.transactionId
                }}, status=200)
        except:
            return JsonResponse({'body': 'GET request failed, please request again'}, status=500)

    return JsonResponse({'body': 'Please "GET" the request!'}, status=400)
