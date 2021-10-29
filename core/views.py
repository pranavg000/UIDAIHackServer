from os import stat
from django.http.response import JsonResponse
from django.shortcuts import render
from rest_framework.parsers import JSONParser
from rest_framework.decorators import api_view
from django.http import JsonResponse
from .models import *
from .decorators import check_token, request_interface
from django.conf import settings
import requests
import json
from pyfcm import FCMNotification
from .utils import getRandAlNum, getRandAl
from math import dist, sin, cos, sqrt, atan2, radians
import logging
import uuid

txnlogger = logging.getLogger('txnlog')
authlogger = logging.getLogger('authlog')

def redactUID(uid):
    return 'X'*8+uid[-4:]

def authlog(message, uid, transactionID=""):
    authlogger.info(f"{transactionID}:{redactUID(uid)}:{message}")

def txnlog(uidToken, message, transactionID="", transaction=None):
    if transaction:
        txnlogger.info(f"{uidToken}:{transaction.transactionID}:{transaction.lender.uidToken}:{transaction.requester.uidToken}:{transaction.state}:{message}")
    else:
        txnlogger.info(f"{uidToken}:{transactionID}::::{message}")



push_notification_service = FCMNotification(api_key=settings.FIREBASE_SERVER_KEY)
radar_api_key = 'prj_test_sk_f07c23cb9ac9fff33d38ccbb366375953cc0abc1'

AUTH_TOKEN_LEN = 16
SHAREABLE_CODE_LEN = 9
ADDRESS_FIELDS = ['co','house','street','lm','lo','vtc','subdist','dist','state','country','pc','po']

def genAuthToken():
    return getRandAlNum(AUTH_TOKEN_LEN)

def genShareableCode():
    shareableCode = ""
    while (shareableCode == "" or AnonProfile.objects.filter(shareableCode=shareableCode).exists()):
        shareableCode = getRandAl(SHAREABLE_CODE_LEN)
    return shareableCode

def callOTPAPI(uid):
    #TODO: OTP API (AN) 

    txnId = uuid.uuid4()
    
    headers = {
        "content-type": "application/json"
    }
    data = {
        "uid": str(uid),
        "txnId": str(txnId)
    }
    getOtpApiUrl = 'https://stage1.uidai.gov.in/onlineekyc/getOtp/'

    response = requests.post(getOtpApiUrl, json=data, headers=headers).json()
    respStatus = response['status']
    respCode = response['errCode']

    if(respStatus and (respStatus == 'y' or respStatus == 'Y')):
        return txnId
    return -1

def verifyOTPAuthAPI(txnId, otp, uid):

    headers = {
        "content-type": "application/json"
    }
    data = {
        "uid": str(uid),
        "txnId": str(txnId),
        "otp": str(otp)
    }
    getAuthApiUrl = 'https://stage1.uidai.gov.in/onlineekyc/getAuth/'
    response = requests.post(getAuthApiUrl, json=data, headers=headers).json()
    # print(">>>>>>>>>>>>>>>>>>>", response)
    if response['status'] and (response['status'] == 'y' or response['status'] == 'Y'):
        return True, uid
    return False, None

def sendPushNotification(deviceID, messageTitle, messageBody, dataMessage=None):
    # return True
    result = push_notification_service.notify_single_device(registration_id=deviceID, message_title=messageTitle, message_body=messageBody)
    result = push_notification_service.notify_single_device(registration_id=deviceID, data_message=dataMessage)
    if result['success'] == 1:
        return True

    return False        # Pray that this never happens

def getDistance(p1, p2):
        # approximate radius of earth in km
        R = 6373.0

        lat1 = radians(p1[0])
        lon1 = radians(p1[1])
        lat2 = radians(p2[0])
        lon2 = radians(p2[1])

        dlon = lon2 - lon1
        dlat = lat2 - lat1

        a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
        c = 2 * atan2(sqrt(a), sqrt(1 - a))

        return R * c    # in km

def getCoord(address):
    addressS = ""
    IGNORE_FIELDS = ['co', 'po', 'lm']
    for field in ADDRESS_FIELDS:
        if field in IGNORE_FIELDS:
            continue
        if address.get(field):
            addressS += ('+'.join(address[field].split())+',+')
    

    addressS = addressS[:-1]

    response = requests.get('https://api.radar.io/v1/geocode/forward?query='+addressS, headers={'Authorization': radar_api_key})
    if response.status_code != 200:
        # print("FFFFFFFFFFFFFFFFFF Geocode failed at ",addressS)
        return False
    coord = json.loads(response.content)['addresses'][0]
    return (coord['latitude'], coord['longitude'])


@api_view(['POST'])
@request_interface(['uid'])
def authUID(request):
    if request.method == 'POST':
        # data = JSONParser.parse(request)
        
        txnId = callOTPAPI(request.data['uid'])
        
        if(txnId == -1):
            authlog(uid=request.data['uid'], transactionID=txnId, message="OTP API request failed")
            return JsonResponse({'txnId': txnId, 'message': 'API request failed, please try again'}, status=500)
        
        authlog(uid=request.data['uid'], transactionID=txnId, message="OTP initiated")
        return JsonResponse({'txnId': txnId}, status=200)

    return JsonResponse({}, status=400)


@api_view(['POST'])
@request_interface(['transactionID', 'otp', 'deviceID', 'publicKey', 'uid'])
def authOTP(request):
    if request.method == 'POST':
        # data = JSONParser.parse(request)

        transactionID = request.data['transactionID']
        uid = request.data['uid']
        authlog(uid=uid, transactionID=request.data['transactionID'], message="OTP verification initiated")

        result, uidToken = verifyOTPAuthAPI(transactionID, request.data['otp'], uid)
        
        if not result:
            authlog(uid=request.data['uid'], transactionID=request.data['transactionID'], message="Invalid OTP")
            return JsonResponse({'body': "Wrong OTP", 'transactionID': transactionID}, status=403)


        authlog(uid=request.data['uid'], transactionID=request.data['transactionID'], message="OTP verified")
        deviceID = request.data['deviceID']
        publicKey = request.data['publicKey']


        if AnonProfile.objects.filter(uidToken=uidToken).exists():
            profile = AnonProfile.objects.get(uidToken=uidToken)
            profile.publicKey = publicKey
            profile.deviceID = deviceID
            profile.save()


            authlog(uid=request.data['uid'], transactionID=request.data['transactionID'], message="Resident already exists. Public key and deviceID updated")
            return JsonResponse({
                'shareableCode': profile.shareableCode, 
                'authToken': profile.authToken, 
                'uidToken': uidToken, 
                'transactionID': transactionID
                }, status=200)

        shareableCode = genShareableCode()
        authToken = genAuthToken()

        AnonProfile.objects.create(
            uidToken=uidToken, 
            authToken=authToken, 
            deviceID=deviceID, 
            publicKey=publicKey, 
            shareableCode=shareableCode
            )
         
        authlog(uid=request.data['uid'], transactionID=request.data['transactionID'], message="New resident created")

        return JsonResponse({
            'shareableCode': shareableCode, 
            'authToken': authToken, 
            'uidToken': uidToken, 
            'transactionID': transactionID
            }, status=200)


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
        transactionID = transaction.transactionID

        request.data['transactionID'] = transactionID       # Used in logging
        txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="New address change request received")

        if sendPushNotification(lender.deviceID, "New Address Request", "Somebody has requested for your address", {'encryptedMessage': request.data['message'], 'transactionID': transaction.transactionID, 'status': transaction.state, 'requesterSC': requester.shareableCode}):
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Address request sent to lender")
            return JsonResponse({'body': 'Request sent to lender', 'transactionID': transactionID }, status=200)
        else:
            transaction.state = 'aborted'
            transaction.save()
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Unable to send request to lender. Aborting")
            return JsonResponse({'body': 'Unable to send request to lender. Aborting', 'transactionID': transactionID}, status=400)

    return JsonResponse({}, status=400)


@api_view(['POST'])
@check_token
@request_interface(['transactionID'])
def rejectRequest(request):
    if request.method == 'POST':
        txnlog(uidToken=request.data['uidToken'], transactionID=request.data['transactionID'], message="Address request rejection initiated by lender")
        try:
            transaction = Transaction.objects.get(transactionID=request.data['transactionID'])
            assert(transaction.state == 'init')
            lender = transaction.lender
            assert(lender == AnonProfile.objects.get(uidToken=request.data['uidToken']))
            
        except:
            txnlog(uidToken=request.data['uidToken'], transactionID=request.data['transactionID'], message="Invalid transactionID. Transaction not rejected")
            return JsonResponse({'body': "Invalid transactionID"}, status=400)

        requester = transaction.requester
        transaction.state = 'rejected'
        transaction.save()
        txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Address request rejected by lender")

        if sendPushNotification(requester.deviceID, "Address request denied", f"Address request denied for TNo: {transaction.transactionID}", {'transactionID': transaction.transactionID, 'status': transaction.state}):
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Rejection notification delivered to requester")
        else:
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Rejection notification could not be delivered to requester")

        return JsonResponse({'body': 'Request denied successfully', 'transactionID': transaction.transactionID }, status=200)
        

    return JsonResponse({}, status=400)


@api_view(['GET'])
@check_token
@request_interface(['shareableCode'])
def getPublicKey(request):
    if request.method == 'GET':
        txnlog(uidToken=request.data['uidToken'], message=f"Public key of SC:{request.data['shareableCode']} requested")
        try:
            profile = AnonProfile.objects.get(shareableCode=request.data['shareableCode'])
            txnlog(uidToken=request.data['uidToken'], message=f"Public key of SC:{request.data['shareableCode']}(uidToken:{profile.uidToken}) supplied")
            return JsonResponse({'publicKey': profile.publicKey}, status=200)
        except:
            txnlog(uidToken=request.data['uidToken'], message="Invalid share code")
            return JsonResponse({'body': "Invalid share code"}, status=400)

    return JsonResponse({}, status=400)


@api_view(['POST'])
@check_token
@request_interface(['transactionID', 'eKYC', 'passcode', 'filename'])
def POSTekyc(request):
    if request.method == 'POST':
        txnlog(uidToken=request.data['uidToken'], transactionID=request.data['transactionID'], message="Address request acceptance initiated by lender")
        transactionID = request.data['transactionID']
        eKYC_enc = request.data['eKYC']
        passcode_enc = request.data['passcode']
        filename = request.data['filename']

        try:
            transaction = Transaction.objects.get(transactionID=transactionID)
            print(transaction.state)
            assert(transaction.state == 'init')
            renterDeviceId = transaction.requester.deviceID
            lender = transaction.lender
            assert(lender == AnonProfile.objects.get(uidToken=request.data['uidToken']))
            transaction.state = 'accepted'
            transaction.save()
            OfflineEKYC.objects.create(
                transactionID=transactionID,
                encryptedEKYC=eKYC_enc,
                encryptedPasscode=passcode_enc,
                filename=filename,
            )
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Address request accepted by lender")

        except:
            txnlog(uidToken=request.data['uidToken'], transactionID=transactionID, message="Invalid transactionID. Address request acceptance failed")
            return JsonResponse({'message': 'Invalid transactionID. Address request acceptance failed', 'transactionID': transactionID}, status=400)

        
        # print(transactionID, eKYC_enc, passcode_enc, filename)

        message_caption = "Address Request Approved!"
        message_body = "Hi There! Landlord has approved your request to share his address, please click the button to get the address"
        message_data = {
            'transactionID': transactionID,
            'status': transaction.state
        }
        if sendPushNotification(renterDeviceId, message_caption, message_body, message_data):
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Acceptance notification delivered to requester")
            return JsonResponse({
                'message':'Hello from the server!', 
                'transactionID': transactionID,
                'status': transaction.state
                }, status=200)

        txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Acceptance notification could not be delivered to requester")
        return JsonResponse({'message': 'Push Notification Failure', 'transactionID': transactionID, 'status': transaction.state}, status=400)

    return JsonResponse({'message': 'Please "POST" the request', 'transactionID': '-1'}, status=400)


@api_view(['GET'])
@check_token
@request_interface(['transactionID'])
def GETekyc(request):
    if request.method == 'GET':
        txnlog(uidToken=request.data['uidToken'], transactionID=request.data['transactionID'], message="eKYC fetch initiated by requested")
        
        transactionID = request.data['transactionID']
        try:
            transaction = Transaction.objects.get(transactionID=transactionID)
            assert(transaction.state == 'accepted')
            requester = transaction.requester
            assert(requester == AnonProfile.objects.get(uidToken=request.data['uidToken']))
            offlineEKYC = OfflineEKYC.objects.get(transactionID=transactionID)
            
            transaction.state = 'shared'
            transaction.save()

            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="eKYC sent to requester")
            
            return JsonResponse({
                'encryptedEKYC': offlineEKYC.encryptedEKYC,
                'encryptedPasscode': offlineEKYC.encryptedPasscode,
                'filename': offlineEKYC.filename,
                'transactionID': offlineEKYC.transactionID,
                'status': transaction.state
                }, status=200)
        except:
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Invalid transactionID. Unable to send eKYC to requester")
            return JsonResponse({'message': 'Invalid transactionID. Unable to send eKYC to requester', 'transactionID': transactionID}, status=500)

    return JsonResponse({'message': 'Please "GET" the request!', 'transactionID': '-1'}, status=400)

@api_view(['POST'])
@check_token
@request_interface(['transactionID', 'oldAddress', 'newAddress', 'gpsCoord', 'uid'])
def updateAddress(request):
    if request.method == 'POST':
        transactionID = request.data['transactionID']
        txnlog(uidToken=request.data['uidToken'], transactionID=transactionID, message="Final address update initiated by requester")
        try:
            
            transaction = Transaction.objects.get(transactionID=transactionID)
            requester = transaction.requester
            assert(requester == AnonProfile.objects.get(uidToken=request.data['uidToken']))
            assert(transaction.state == 'shared')
        except:
            txnlog(uidToken=request.data['uidToken'], transactionID=transactionID, message="Invalid transactionID")
            return JsonResponse({'body': "Invalid transactionID"}, status=400)

        txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Address verification initiated")
        oldCoord = getCoord(request.data['oldAddress'])
        if not oldCoord:
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Lender's address is invalid")
            return JsonResponse({'body': 'Old address invalid', 'transactionID': transactionID, 'status': transaction.state}, status=400)
        
        newCoord = getCoord(request.data['newAddress'])
        if not newCoord:
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Requester's new address is invalid")
            return JsonResponse({'body': 'New address invalid', 'transactionID': transactionID, 'status': transaction.state}, status=400)
        
        gpsCoord = request.data['gpsCoord']
        distance1 = getDistance(oldCoord, newCoord)
        distance2 = getDistance(gpsCoord, newCoord)
        # print(gpsCoord, distance1, distance2)
        if distance1 < 0.4 and distance2 < 1:
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Requester's new address verified")
            try:
                UpdatedAddress.objects.create(**(request.data['newAddress']), uid=request.data['uid'], transactionID=transactionID)
                transaction.state = 'commited'
                transaction.save()
                txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Requester's new address committed to DB")

                if sendPushNotification(transaction.lender.deviceID, "Requester's address has been updated", f"Requester's address for TNo: {transactionID} has been updated", {'requesterSC': requester.shareableCode, 'newAddress': request.data['newAddress'], 'transactionID': transaction.transactionID, 'status': transaction.state}):
                    txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Address update notification sent to Lender")
                else:
                    txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Address update notification could not be sent to Lender")
                return JsonResponse({'transactionID': transactionID, 'status': transaction.state}, status=200)
            except:
                txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Requester's new address could not be committed to DB")
                return JsonResponse({'body': 'Repeated TransactionID', 'transactionID': transactionID, 'status': transaction.state}, status=400)

        
        txnlog(uidToken=request.data['uidToken'], transaction=transaction, message=f"Addresses are too far. Distance from gps: {distance2}, dist from lender's address: {distance1}")
        return JsonResponse({'body': f'Addresses are too far. Dist from gps: {distance2}, dist from oldAddress: {distance1}', 'transactionID': transactionID, 'status': transaction.state}, status=400)

    return JsonResponse({}, status=400)



