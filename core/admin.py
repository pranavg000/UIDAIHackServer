from django.contrib import admin
from .models import *

admin.site.register(AnonProfile)
admin.site.register(Ekyc)
admin.site.register(Transaction)
admin.site.register(UpdatedAddress)
admin.site.register(OfflineEKYC)
