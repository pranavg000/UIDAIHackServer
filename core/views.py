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
from hashlib import sha256
import base64
import zipfile
import io
import xml.etree.ElementTree as ET
from base64 import b64decode
from base64 import b64encode

# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_v1_5

txnlogger = logging.getLogger('txnlog')
authlogger = logging.getLogger('authlog')

def redactUID(uid):
    """Redacts UID of resident before storing in logs

    Args:
        uid (str): UID of resident

    Returns:
        redactedUID (str)
    """

    return 'X'*8+uid[-4:]

def authlog(message, uid, transactionID=""):
    """Logs auth API calls

    Args:
        message (str): Message to log
        uid (str): UID of resident
        transactionID (str): TransactionID of the auth transaction
            (default is "")
    """

    authlogger.info(f"{transactionID}:{redactUID(uid)}:{message}")

def txnlog(uidToken, message, transactionID="", transaction=None):
    """Logs all address request/update transactions

    Args:
        uidToken (str): UID token of resident
        message (str): Message to log
        transactionID (str): TransactionID of the address transaction
            (default is "")
        transaction (Transaction): Current ongoing transaction 
    """

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
    """Generates random alphanumeric Auth Token

    Args:
        void

    Returns:
        authToken (str): randomly generated alphanumeric auth token
    """

    return getRandAlNum(AUTH_TOKEN_LEN)

def genShareableCode():
    """Generates random alphabetic unique shareable code

    Args:
        void

    Returns:
        shareableCode (str): random alphabetic unique shareable code
    """
    
    shareableCode = ""
    while (shareableCode == "" or AnonProfile.objects.filter(shareableCode=shareableCode).exists()):
        shareableCode = getRandAl(SHAREABLE_CODE_LEN)
    return shareableCode

def callOTPAPI(uid):
    """Calls UIDAI OTP API to send OTP to resident

    Args:
        uid (str): UID of resident

    Returns:
        txnID (str): txnID if OTP sent successfully, -1 otherwise
    """

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

    if(respStatus and (respStatus == 'y' or respStatus == 'Y')):
        return txnId
    return "-1"

def verifyOTPAuthAPI(txnId, otp, uid):
    """Calls UIDAI Auth API for OTP verification

    Args:
        txnId (str): Transaction ID
        otp (str): OTP entered by resident
        uid (str): UID of resident

    Returns:
        status (tuple[bool, code]): status of verification and additional info code
    """

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
        return True, sha256(uid.encode()).hexdigest()
    if response['errCode']:
        return False, response['errCode']
    return False, None

def sendPushNotification(deviceID, messageTitle, messageBody, dataMessage=None):
    """Send push notification to a device using FCM

    Args:
        deviceID (str): device registration token for FCM
        messageTitle (str): Title of noitification
        messageBody (str): Body of noitification
        dataMessage (dict[str, str]): Addition data to be sent to the device

    Returns:
        status (bool): True if successful, False otherwise
    """

    result = push_notification_service.notify_single_device(registration_id=deviceID, message_title=messageTitle, message_body=messageBody)
    result = push_notification_service.notify_single_device(registration_id=deviceID, data_message=dataMessage)

    if result['success'] == 1:
        return True
    return False

def getDistance(point1, point2):
        """Geographical distance between 2 points on the earth

        Args:
            point1 (list[float]): First point in [lat, long] format
            point2 (list[float]): Second point in [lat, long] format

        Returns:
            dist (float): Geographical distance (in km) between point1 & point2
        """

        R = 6373.0      # Approx radius of earth (in km)

        lat1 = radians(point1[0])
        lon1 = radians(point1[1])
        lat2 = radians(point2[0])
        lon2 = radians(point2[1])

        dlon = lon2 - lon1
        dlat = lat2 - lat1

        a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
        c = 2 * atan2(sqrt(a), sqrt(1 - a))

        return R * c    # in km

# Returns (lat, long) of an address
def getCoord(address):
    """Calls the geocode API to get (lat, long) of an address

    Args:
        address (dict[str, str]): Addrress in UIDAI address format

    Returns:
        [lat, long] (list[float, float]): a list representing latitude and longitude
    """

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



def getAddressHashFromOfflineEKyc(eekyc, passcode):
    ekycx = eekyc["eKycXML"]
    filename = eekyc['filename'].split('.')[0]
    dekyc = base64.b64decode(ekycx)
    z = zipfile.ZipFile(io.BytesIO(dekyc))
    z.setpassword(passcode.encode())
    ez = {name: z.read(name) for name in z.namelist()}
    xmls = ez[filename+'.xml']
    root = ET.fromstring(xmls)
    response_dict = root.find('UidData').find('Poa').attrib
    co = response_dict['careof']
    response_dict['co'] = co
    del response_dict['careof']
    return sha256(str(response_dict).encode()).hexdigest()

def encryptByPublicKey(s, public_key):
    key = b64decode(public_key)
    key = RSA.importKey(key)

    cipher = PKCS1_v1_5.new(key)
    ciphertext = b64encode(cipher.encrypt(bytes(s, "utf-8")))

    return ciphertext

@api_view(['POST'])
@request_interface(['uid'])
def authUID(request):
    """API endpoint for initiating authentication process with otp

    Client app sends the uid of the resident and UIDAI OTP API is called 
    to send OTP to the registed mobile number.
    """

    if request.method == 'POST':
        # data = JSONParser.parse(request)
        
        transactionID = callOTPAPI(request.data['uid'])
        
        if(transactionID == "-1"):
            authlog(uid=request.data['uid'], transactionID=transactionID, message="OTP API request failed")
            return JsonResponse({'transactionID': transactionID, 'message': 'API request failed, please try again'}, status=501)
        
        authlog(uid=request.data['uid'], transactionID=transactionID, message="OTP initiated")
        return JsonResponse({'transactionID': transactionID, 'message': 'OTP initiated'}, status=200)

    return JsonResponse({}, status=400)


@api_view(['POST'])
@request_interface(['transactionID', 'otp', 'deviceID', 'publicKey', 'uid'])
def authOTP(request):
    """API endpoint for OTP verification

    Client app sends transactionID, otp and other metadata of the client 
    app. UIDAI Auth API is called to verify OTP. The authToken and 
    shareable code is returned to the client app.
    """

    if request.method == 'POST':
        # data = JSONParser.parse(request)

        transactionID = request.data['transactionID']
        uid = request.data['uid']
        authlog(uid=uid, transactionID=request.data['transactionID'], message="OTP verification initiated")

        result, uidToken = verifyOTPAuthAPI(transactionID, request.data['otp'], uid)
        
        if not result:
            if uidToken == '400':
                authlog(uid=request.data['uid'], transactionID=request.data['transactionID'], message="Invalid OTP")
                return JsonResponse({'body': "Wrong OTP", 'transactionID': transactionID}, status=403)
            elif uidToken == '403':
                authlog(uid=request.data['uid'], transactionID=request.data['transactionID'], message="Maxmimum trials for OTP check reached, please request OTP again")
                return JsonResponse({'body': "Maxmimum trials for OTP check reached, please request OTP again", 'transactionID': transactionID}, status=503)
            else:
                authlog(uid=request.data['uid'], transactionID=request.data['transactionID'], message=f"Error in AuthAPI Call, error code: {uidToken}")
                return JsonResponse({'body': "Internal Server Error", 'transactionID': transactionID}, status=501)

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


    return JsonResponse({}, status=400)


@api_view(['POST'])
@check_token
@request_interface(['receiverSC', 'message'])
def sendRequest(request):
    """API endpoint for initiating a Address Request

    Client app sends the shareable code of the lender and an encrypted 
    message containing his information (such as name, phone number, etc). 
    A new transaction is initiated. Push notification is sent to the lender.
    TransactionID is shared with both the involved parties.
    """
    if request.method == 'POST':
        try:
            lender = AnonProfile.objects.get(shareableCode=request.data['receiverSC'])
            requester = AnonProfile.objects.get(uidToken=request.data['uidToken'])
            
        except:
            return JsonResponse({'body':'Invalid uidToken / Receiver Share Code'}, status=403)

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
            return JsonResponse({'body': 'Unable to send request to lender. Aborting', 'transactionID': transactionID}, status=502)

    return JsonResponse({}, status=400)


@api_view(['POST'])
@check_token
@request_interface(['transactionID'])
def rejectRequest(request):
    """API endpoint used by lender to reject the address request

    Terminates(rejects) the transaction. Notification sent to 
    both the involved parties.
    """
    if request.method == 'POST':
        txnlog(uidToken=request.data['uidToken'], transactionID=request.data['transactionID'], message="Address request rejection initiated by lender")
        try:
            transaction = Transaction.objects.get(transactionID=request.data['transactionID'])
            assert(transaction.state == 'init')
            lender = transaction.lender
            assert(lender == AnonProfile.objects.get(uidToken=request.data['uidToken']))
            
        except:
            txnlog(uidToken=request.data['uidToken'], transactionID=request.data['transactionID'], message="Invalid transactionID. Transaction not rejected")
            return JsonResponse({'body': "Invalid transactionID"}, status=403)

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


@api_view(['POST'])
@check_token
@request_interface(['shareableCode'])
def getPublicKey(request):
    if request.method == 'POST':
        txnlog(uidToken=request.data['uidToken'], message=f"Public key of SC:{request.data['shareableCode']} requested")
        try:
            profile = AnonProfile.objects.get(shareableCode=request.data['shareableCode'])
            txnlog(uidToken=request.data['uidToken'], message=f"Public key of SC:{request.data['shareableCode']}(uidToken:{profile.uidToken}) supplied")
            return JsonResponse({'publicKey': profile.publicKey}, status=200)
        except:
            txnlog(uidToken=request.data['uidToken'], message="Invalid share code")
            return JsonResponse({'body': "Invalid share code"}, status=403)

    return JsonResponse({}, status=400)


@api_view(['POST'])
@check_token
@request_interface(['transactionID', 'txnNumber', 'otp', 'uid'])
def POSTekyc(request):
    if request.method == 'POST':
        txnlog(uidToken=request.data['uidToken'], transactionID=request.data['transactionID'], message="Address request acceptance initiated by lender")
        transactionID = request.data['transactionID']
        uid = request.data['uid']
        otp = request.data['otp']
        txnNumber = request.data['txnNumber']
        passcode = str(uuid.uuid4())[-4:]

        try:
            transaction = Transaction.objects.get(transactionID=transactionID)
            # print(transaction.state)
            assert(transaction.state == 'init')
            requesterDeviceId = transaction.requester.deviceID
            lender = transaction.lender
            assert(lender == AnonProfile.objects.get(uidToken=request.data['uidToken']))

            #new flow to call AAdhaar eKYC(offline) API
            headers = {
                "content-type": "application/json"
            }
            data = {
                "uid": str(uid),
                "txnNumber": str(txnNumber),
                "otp": str(otp),
                "shareCode": str(passcode)
            }
            # print("data", data)
            response = requests.post(
                'https://stage1.uidai.gov.in/eAadhaarService/api/downloadOfflineEkyc',
                json=data,
                headers=headers,
            ).json()

            if(response['status'] == 'Success' or response['status'] == 'success'):
                eekyc = response['eKycXML']
                lenderAddress = getAddressHashFromOfflineEKyc(eekyc, passcode);
                encrypted_passcode = encryptByPublicKey(passcode, lender.publicKey)

                #store in the db
                try:
                    OfflineEKYC.objects.create(
                        transactionID=transactionID,
                        encryptedEKYC=lenderAddress,
                        encryptedPasscode=encrypted_passcode,
                    )
                except:
                    txnlog(uidToken=request.data['uidToken'], transactionID=transactionID, message="Database storage failure. Address request acceptance failed")
                    return JsonResponse({
                        'message': 'Invalid transactionID. Address request acceptance failed', 
                        'transactionID': transactionID
                        }, status=500)

                transaction.state = 'accepted'
                transaction.save()
                txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Address request accepted by lender")

            else:
                txnlog(uidToken=request.data['uidToken'], transactionID=transactionID, message="Aadhaar API request failed")
                return JsonResponse({
                    'message': 'Aadhaar API failure. Address request acceptance failed', 
                    'transactionID': transactionID
                    }, status=501)

        except:
            txnlog(uidToken=request.data['uidToken'], transactionID=transactionID, message="Invalid transactionID. Address request acceptance failed")
            return JsonResponse({
                'message': 'Invalid transactionID. Address request acceptance failed', 
                'transactionID': transactionID
                }, status=403)

        
        message_caption = "Address Request Approved!"
        message_body = "Hi There! Lender has approved your request to share his address, please click the button to get the address"
        message_data = {
            'transactionID': transactionID,
            'status': transaction.state
        }
        if sendPushNotification(requesterDeviceId, message_caption, message_body, message_data):
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Acceptance notification delivered to requester")
            return JsonResponse({
                'message':'Hello from the server!', 
                'transactionID': transactionID,
                'status': transaction.state,
                }, status=200)

        txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Acceptance notification could not be delivered to requester")
        return JsonResponse({
            'message': 'Push Notification Failure', 
            'transactionID': transactionID, 'status': transaction.state
            }, status=502)

    return JsonResponse({
        'message': 'Please "POST" the request', 
        'transactionID': '-1'
        }, status=400)


@api_view(['POST'])
@check_token
@request_interface(['transactionID'])
def GETekyc(request):
    if request.method == 'POST':
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
                'transactionID': offlineEKYC.transactionID,
                'status': transaction.state,
                'filename': "null"
                }, status=200)
        except:
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Invalid transactionID. Unable to send eKYC to requester")
            return JsonResponse({'message': 'Invalid transactionID. Unable to send eKYC to requester', 'transactionID': transactionID}, status=403)

    return JsonResponse({'message': 'Please "GET" the request!', 'transactionID': '-1'}, status=400)

@api_view(['POST'])
@check_token
@request_interface(['transactionID', 'oldAddress', 'newAddress', 'gpsCoord', 'uid'])
def updateAddress(request):
    """API endpoint for the new address verification and storage

    Requester sends the landlord's address, new address and gps coordinates to the 
    server for verification. After verification, the updated address records are 
    stored.
    """
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
            return JsonResponse({'body': "Invalid transactionID"}, status=403)

        txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Address verification initiated")
        oldCoord = getCoord(request.data['oldAddress'])

        try:
            offlineEKYC = OfflineEKYC.objects.get(transactionID=transactionID)
            encrEkycOld = offlineEKYC.encryptedEKYC
            checkSum = (sha256(str(request.data['oldAddress']).encode()).hexdigest() == encrEkycOld)
        except:
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Database read failure")
            return JsonResponse({'body': 'Database read faliure, address not committed', 'transactionID': transactionID, 'status': transaction.state}, status=500)

        if not oldCoord and checkSum:
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Lender's address is invalid")
            return JsonResponse({'body': 'Old address invalid', 'transactionID': transactionID, 'status': transaction.state}, status=403)
        
        newCoord = getCoord(request.data['newAddress'])
        if not newCoord:
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Requester's new address is invalid")
            return JsonResponse({'body': 'New address invalid', 'transactionID': transactionID, 'status': transaction.state}, status=403)
        
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
                txnlog(uidToken=request.data['uidToken'], transaction=transaction, message=f"lender's address for auditing - {str(request.data['oldAddress'])}")
                if sendPushNotification(transaction.lender.deviceID, "Requester's address has been updated", f"Requester's address for TNo: {transactionID} has been updated", {'requesterSC': requester.shareableCode, 'newAddress': request.data['newAddress'], 'transactionID': transaction.transactionID, 'status': transaction.state}):
                    txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Address update notification sent to Lender")
                else:
                    txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Address update notification could not be sent to Lender")
                return JsonResponse({'body': 'Success', 'transactionID': transactionID, 'status': transaction.state}, status=200)
            except:
                txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Requester's new address could not be committed to DB")
                return JsonResponse({'body': 'Repeated TransactionID', 'transactionID': transactionID, 'status': transaction.state}, status=409)

        
        txnlog(uidToken=request.data['uidToken'], transaction=transaction, message=f"Addresses are too far. Distance from gps: {distance2}, dist from lender's address: {distance1}")
        return JsonResponse({'body': f'Addresses are too far. Dist from gps: {distance2}, dist from oldAddress: {distance1}', 'transactionID': transactionID, 'status': transaction.state}, status=401)

    return JsonResponse({}, status=400)


@api_view(['POST'])
@check_token
@request_interface(['transactionID'])
def withdrawRequest(request):
    """API endpoint used by requester to withdraw his address request

    Terminates(withdrawn) the transaction. Notification sent to 
    both the involved parties.
    """
    if request.method == 'POST':
        txnlog(uidToken=request.data['uidToken'], transactionID=request.data['transactionID'], message="Address request withdraw initiated by requester")
        try:
            transaction = Transaction.objects.get(transactionID=request.data['transactionID'])
            assert(transaction.state != 'rejected' or transaction.state != 'aborted' or transaction.state != 'commited')
            requester = transaction.requester
            assert(requester == AnonProfile.objects.get(uidToken=request.data['uidToken']))
            
        except:
            txnlog(uidToken=request.data['uidToken'], transactionID=request.data['transactionID'], message="Invalid transactionID. Transaction not withdrawn")
            return JsonResponse({'body': "Invalid transactionID"}, status=403)

        lender = transaction.lender
        transaction.state = 'withdrawn'
        transaction.save()
        txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Address request withdrawn by requester")

        if sendPushNotification(lender.deviceID, "Address request withdrawn", f"Address request withdrawn for TNo: {transaction.transactionID}", {'transactionID': transaction.transactionID, 'status': transaction.state}):
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Withdraw notification delivered to lender")
        else:
            txnlog(uidToken=request.data['uidToken'], transaction=transaction, message="Withdraw notification could not be delivered to lender")

        return JsonResponse({'body': 'Request withdrawn successfully', 'transactionID': transaction.transactionID }, status=200)
        

    return JsonResponse({}, status=400)



