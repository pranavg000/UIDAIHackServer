from django.urls import path
from . import views

urlpatterns = [
    path('authuid', views.authUID, name='authuid'),
    path('authotp', views.authOTP, name='authotp'),
    # path('authfinal', views.authFinal, name='authfinal'),
    path('sendrequest', views.sendRequest, name='sendRequest'),
    # path('respondrequest', views.respondRequest, name='respondRequest'),
    # path('getpublickey', views.getPublicKey, name='getPublicKey'),
    # path('oekyc', views.oekyc, name='oekyc'),
    # path('updateaddress', views.updateAddress, name='updateAddress'),
    # path('sendmessage', views.sendMessage, 'sendMessage'),
    path('postekyc', views.POSTekyc, name='POSTekyc'),
    path('getekyc', views.GETekyc, name='GETekyc'),
    
]
