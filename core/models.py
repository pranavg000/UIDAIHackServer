from django.db import models
from .choices import TRANSACTION_STATES
from .utils import getRandAlNum

TRANSACTION_NUM_LEN = 10

class AnonProfile(models.Model):
    uidToken = models.CharField(max_length=30, primary_key=True)    # UIDAI UID Token
    authToken = models.CharField(max_length=256)                        # Token for communication with client app
    deviceID = models.CharField(max_length=256, unique=True)                         # For FCM
    publicKey = models.CharField(max_length=1024)
    shareableCode = models.CharField(max_length=1024, unique=True)

    def __str__(self):
        return 'AnonProfile:' + self.uidToken

# Dummy table for testing purposes. Will delete in final build
class OTPAPISim(models.Model):
    transactionID = models.CharField(max_length=12, unique=True)
    uid = models.CharField(max_length=12, primary_key=True)
    uidToken = models.CharField(max_length=32, unique=True)


class Ekyc(models.Model):
    ekycFile = models.FileField(upload_to='')   # Encrypted by passcode
    encPassCode = models.IntegerField()         # Encrypted by public key


class Transaction(models.Model):
    # TransactionID - Autogenerated primary key

    # Not allowing deletion of a profile if transaction has an entry
    transactionID = models.CharField(max_length=32, unique=True)
    requester = models.ForeignKey(AnonProfile, related_name='requester', on_delete=models.RESTRICT)
    lender = models.ForeignKey(AnonProfile, related_name='lender', on_delete=models.RESTRICT)
    timestamp = models.DateTimeField(auto_now_add=True)     # Start time of the transaction
    state = models.CharField(
		max_length=10,
        choices=TRANSACTION_STATES,
        default='init',
	)

    def save(self, *args, **kwargs):
        # Setting a random unique transactionID
        if not self.pk:
            # This code only happens if the objects is
            # not in the database yet. Otherwise it would
            # have pk
            transNo = ""
            while(transNo == "" or Transaction.objects.filter(transactionID=transNo)):
                transNo = getRandAlNum(TRANSACTION_NUM_LEN)

            self.transactionID = transNo
        super(Transaction, self).save(*args, **kwargs)

    def __str__(self):
        return f'Trans:{self.transactionID}-{self.state}'



class Notifications(models.Model):
    receiver = models.ForeignKey(AnonProfile, related_name='notifReceiver', on_delete=models.CASCADE)
    messageTitle = models.CharField(max_length=64)
    messageBody = models.CharField(max_length=512)
    timestamp = models.DateTimeField(auto_now_add=True)



class OfflineEKYC(models.Model):
    transactionID = models.CharField(max_length=64, primary_key=True)
    encryptedEKYC = models.TextField(blank=False, null=False)
    encryptedPasscode = models.TextField(blank=False, null=False)
    filename = models.CharField(max_length=50)


# co – “Care of” person’s name if any
# house House identifier if any
# street – Street name if any
# m – Landmark if any
# loLocality if any
# vtc – Name of village or town or city
# subdist – Sub-District name
# dist – District name
# state – State name
# country – Country name
# c – Postal pin code
#  po – Post Office name if any
class UpdatedAddress(models.Model):
    transactionID = models.CharField(max_length=64, primary_key=True)
    uid = models.CharField(max_length=12)

    # Address starts from here
    co = models.CharField(max_length=1024, null=True, blank=True)
    house = models.CharField(max_length=256, null=True, blank=True)
    street = models.CharField(max_length=256, null=True, blank=True)
    lm = models.CharField(max_length=256, null=True, blank=True)
    loc = models.CharField(max_length=256, null=True, blank=True)
    vtc = models.CharField(max_length=256)
    subdist = models.CharField(max_length=256)
    dist = models.CharField(max_length=256)
    state = models.CharField(max_length=256)
    country = models.CharField(max_length=256)
    pc = models.IntegerField()
    po = models.CharField(max_length=512, null=True, blank=True)

    def __str__(self):
        return f'UpdatedAddress TNo:{self.transactionID}'












