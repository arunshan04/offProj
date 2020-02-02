from django.urls import path,include
from . import views


urlpatterns = [
    path('', views.index, name='index'),
    path('login', views.user_login, name='login'),
    path('logout', views.user_logout, name='login'),
    path('register', views.register, name='register'),
    path('forgotPassword', views.forgotPassword, name='forgotPassword'),
    path('index', views.index, name='index'),
    path('forms', views.myForms, name='forms'),
    path('activate/<slug:uidb64>/<slug:token>/', views.activate, name='activate'),
    path('passwordReset/<slug:uidb64>/<slug:token>/', views.passwordReset, name='passwordReset'),

]
    
