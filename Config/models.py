from django.db import models


class Countries(models.Model):
    Region=models.CharField(max_length=5)
    Name=models.CharField(max_length=20)
    Name_CC=models.CharField(max_length=2)
    cntry_cde=models.CharField(max_length=3)

    def __str__(self):
        return self.Name


# Create your models here.
class Application(models.Model):
    AppCSID=models.CharField(max_length=6)
    AppName=models.CharField(max_length=50)
    AppRegion=models.CharField(max_length=50,default='')
    AppCountries=models.ManyToManyField(Countries)
    AppContacts=models.CharField(max_length=500)
    AppManager=models.CharField(max_length=500)
    AppSupportContacts=models.CharField(max_length=500)
    AppSupportManager=models.CharField(max_length=500)
    serviceNowL1L2=models.CharField(max_length=500)
    serviceNowL3=models.CharField(max_length=500)
    serviceNowBatch=models.CharField(max_length=500)

    def __str__(self):
        return self.AppName
    
class ServerConfig(models.Model):
    appName=models.ForeignKey(Application,on_delete=models.SET_NULL, null=True)
    appSiteData=(('Prod','PROD'),('Cob','COB'))
    appSite=models.CharField(max_length=4,choices=appSiteData,blank=True,help_text='Choose App Site',)
    Primary=models.BooleanField(default=True)
    hostName=models.CharField(max_length=30)
    dnsName=models.CharField(max_length=100)


    def __str__(self):
        return self.hostName

class ndmDetails(models.Model):
    Server=models.ForeignKey(ServerConfig,on_delete=models.SET_NULL, null=True)
    NodeName=models.CharField(max_length=40)
    LogDir=models.CharField(max_length=200)

    def __str__(self):
        return self.NodeName
