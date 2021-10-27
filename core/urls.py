from django.urls import path
from . import views

urlpatterns = [
    path('auth', views.auth, name='auth'),
    path('sendrequest', views.sendRequest, name='sendRequest'),
    # path('respondrequest', views.respondRequest, name='respondRequest'),
    # path('getpublickey', views.getPublicKey, name='getPublicKey'),
    # path('oekyc', views.oekyc, name='oekyc'),
    # path('updateaddress', views.updateAddress, name='updateAddress'),
    # path('sendmessage', views.sendMessage, 'sendMessage'),
]
