from django.http.response import JsonResponse
from django.shortcuts import render
from rest_framework.parsers import JSONParser
from rest_framework.decorators import api_view
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import *
from .decorators import check_token, request_interface
from django.conf import settings
from django.core.files.storage import default_storage

from pyfcm import FCMNotification
from .utils import getRandAlNum, getRandAl

push_notification_service = FCMNotification(api_key=settings.FIREBASE_SERVER_KEY)


AUTH_TOKEN_LEN = 16
SHAREABLE_CODE_LEN = 9

def genAuthToken():
    return getRandAlNum(AUTH_TOKEN_LEN)

def genShareableCode():
    shareableCode = ""
    while (shareableCode == "" or AnonProfile.objects.filter(shareableCode=shareableCode).exists()):
        shareableCode = getRandAl(SHAREABLE_CODE_LEN)
    return shareableCode

def callOTPAPI(uid):
    #TODO: OTP API (AN) 
    transactionNo = ""
    while(transactionNo=="" or OTPAPISim.objects.filter(transactionNo=transactionNo).exists()):
        transactionNo = getRandAlNum(5)
    
    
    if OTPAPISim.objects.filter(uid=uid).exists():
        banda = OTPAPISim.objects.get(uid=uid)
        banda.transactionNo = transactionNo
        banda.save()
        return transactionNo
    
    uidToken = ""
    while(uidToken=="" or OTPAPISim.objects.filter(uidToken=uidToken).exists()):
        uidToken = getRandAlNum(16)

    OTPAPISim.objects.create(uid=uid, transactionNo=transactionNo, uidToken=uidToken)

    return transactionNo

def verifyOTPAuthAPI(transactionNo, otp):
    if otp == '12345':
        if OTPAPISim.objects.filter(transactionNo=transactionNo).exists():
            uidToken = OTPAPISim.objects.get(transactionNo=transactionNo).uidToken
            return True, uidToken
    return False, None

def sendPushNotification(deviceID, messageTitle, messageBody, dataMessage=None):
    # return True
    result = push_notification_service.notify_single_device(registration_id=deviceID, message_title=messageTitle, message_body=messageBody, data_message=dataMessage)
    if result['success'] == 1:
        return True

    return False        # Pray that this never happens


@api_view(['POST'])
@request_interface(['uid'])
def authUID(request):
    if request.method == 'POST':
        # data = JSONParser.parse(request)
        
        transactionNo = callOTPAPI(request.data['uid'])
        
        return JsonResponse({'transactionNo': transactionNo}, status=200)
    return JsonResponse({}, status=400)


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


@api_view(['POST'])
@check_token
@request_interface(['receiverSC', 'message'])
def sendRequest(request):
    if request.method == 'POST':
        try:
            lender = AnonProfile.objects.get(shareableCode=request.data['receiverSC'])
            requester = AnonProfile.objects.get(uidToken=request.data['uidToken'])
            
        except:
            return JsonResponse({}, status=400)

        Transaction.objects.filter(lender=lender, requester=requester).update(state='aborted')
        transaction = Transaction.objects.create(lender=lender, requester=requester)
        if sendPushNotification(lender.deviceID, "New Address Request", "New address request has been initiated", {'encryptedMessage': request.data['message']}):
            return JsonResponse({'body': 'Request sent to lender', 'transactionNo': transaction.transactionNo }, status=200)
        else:
            transaction.state = 'aborted'
            transaction.save()
            return JsonResponse({'body': 'Unable to send request to lender. Aborting'}, status=400)

    return JsonResponse({}, status=400)


@api_view(['POST'])
@check_token
@request_interface(['transactionNo'])
def rejectRequest(request):
    if request.method == 'POST':
        try:
            transaction = Transaction.objects.get(transactionNo=request.data['transactionNo'])
        except:
            return JsonResponse({'transactionNo': transaction.transactionNo}, status=400)

        requester = transaction.requester
        transaction.state = 'rejected'
        transaction.save()

        sendPushNotification(requester.deviceID, "Address request denied", f"Address request denied for TNo: {transaction.transactionNo}", {'transactionNo': transaction.transactionNo})
        return JsonResponse({'body': 'Request denied successfully', 'transactionNo': transaction.transactionNo }, status=200)
        

    return JsonResponse({}, status=400)


@api_view(['GET'])
@check_token
@request_interface(['shareableCode'])
def getPublicKey(request):
    if request.method == 'GET':
        try:
            profile = AnonProfile.objects.get(shareableCode=request.data['shareableCode'])
            return JsonResponse({'publicKey': profile.publicKey}, status=200)
        except:
            return JsonResponse({'body': "Invalid share code"}, status=400)

    return JsonResponse({}, status=400)


@api_view(['POST'])
@check_token
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
@check_token
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
