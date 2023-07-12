from django.contrib import admin
from django.urls import path
from . import views
from login.views import packet_list

urlpatterns = [
    path ('', views.home,name="home"),
    path ('signUp',views.signUp, name="signUp"),
    path ('signIn',views.signIn, name="signIn"),
    path ('signOut',views.signOut, name="signOut"),
    path('packets/', packet_list, name='packet_list'),
]
