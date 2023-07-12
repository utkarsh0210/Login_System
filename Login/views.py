from django.shortcuts import redirect,render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout

from .pkt import manipulation

def home(request):
    return render(request,"login/index.html")

def signUp(request):

    if request.method =="POST":
        username = request.POST['username']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        email = request.POST['email']
        password = request.POST['password']
        pass2 = request.POST['re_enterpassword']

        myuser=User.objects.create_user(username,email,password)
        myuser.firstname=firstname
        myuser.lastname=lastname

        myuser.save()

        messages.success(request,"Account created successfully.")
        
        return redirect('signIn')
    return render(request,"login/signUp.html")

def signIn(request):

    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate()
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request,user)
            firstname=user.first_name
            return render(request, "login/index.html")

        else:
            messages.error(request, "Wrong Credentials")
            return redirect('home')
        

    return render(request,"login/signIn.html")

def packet_list(request):
    packets = manipulation()
    return render(request, 'login/packet_list.html', {'packets': packets})

def signOut(request):
    logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect('home')
