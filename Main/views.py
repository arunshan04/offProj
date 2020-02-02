from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm,PasswordResetForm,SetPasswordForm,PasswordChangeForm
from django.contrib.auth.models import User
from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.utils.encoding import force_text
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseRedirect, HttpResponse
from django.views.decorators.csrf import csrf_protect
from django.template import RequestContext
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from six import text_type
from django.contrib import messages
from django.core.mail import send_mail, get_connection



# Create your views here.
@csrf_protect
def user_login(request):
    if request.method=='POST' :
        username, password = request.POST.get('username'), request.POST.get('password')
        if User.objects.filter(username=username).exists():
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request,user)
                    return HttpResponseRedirect(reverse('index'))
                else:
                    messages.warning(request,'Account is InActive. Please Activate using the link shared in the Email')
            else:
                messages.error(request,'User Password Error')
        else:
            messages.error(request,'User Does Not Exists. Please Singup...')
    return render(request, 'login.html')

class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            text_type(user.pk) + text_type(timestamp)         )

account_activation_token = AccountActivationTokenGenerator()

def register(request):
    if request.method  == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.refresh_from_db()
            user.email=user.username+'@gmail.com'
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            subject = 'Please Activate Your Account'
            message = render_to_string('activation_request.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                # method will generate a hash value with user related data
                'token': account_activation_token.make_token(user),
            })
            user.email_user(subject, message)
            messages.success(request,'User Creation Success. Please check Mail For Activation')
        else:
            messages.error(request, 'User Already Exists.. Please Login to Continue')  # <-
    return render(request, 'register.html')


@login_required(login_url='/login')
def user_logout(request):
    logout(request)
    print('User Loggedout')
    return HttpResponseRedirect(reverse('index'))

@login_required(login_url='/login')
def index(request):
    return render(request, 'content.html')

@login_required(login_url='/login')
def myForms(request):
    return render(request, 'forms.html')

def forgotPassword(request):
    if request.method=='POST':
        try:
            user=User.objects.get(username=request.POST.get('username'))
        except (TypeError, ValueError, OverflowError,User.DoesNotExist):
            user = None
            messages.error(request,'User Does Not Exists in the System. Please Singnup')
        if user is not None:
            subject = 'Account Password Reset'
            current_site = get_current_site(request)
            message = render_to_string('password_reset.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    # method will generate a hash value with user related data
                    'token': account_activation_token.make_token(user),
                })
            user.email_user(subject, message)
            messages.success(request,'Password Reset Link Sent to Registered Email..')
            print('MailSent')
    return render(request, 'forgotPassword.html')



def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError,User.DoesNotExist):
        user = None
    # checking if the user exists, if the token is valid.
    if user is not None and account_activation_token.check_token(user, token):
        # if valid set active true 
        user.is_active = True
        # set signup_confirmation true
        user.save()
        login(request, user)
        return redirect('/index')
    else:
        return render(request, 'activation_invalid.html')


def passwordReset(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError,User.DoesNotExist):
        user = None
        messages.error(request,'User Does Not Exists in the System. Please Singup')
        return HttpResponseRedirect('/forgotPassword')
    if request.method=='POST':
        if user is not None and account_activation_token.check_token(user, token):
            form=SetPasswordForm(user=user, data=request.POST)
            if form.is_valid():
                form.save()
                messages.success(request,'Password Reset Completed SuccessFully...')
                return HttpResponseRedirect('/login')
            else:
                messages.error(request,'Passwords are Does not Match or Not Satisifing the Requirements..')
        else:
            messages.error(request,'Invalid Token or Reset Link')
            return HttpResponseRedirect('/forgotPassword')
    return render(request, 'newPassword.html')
