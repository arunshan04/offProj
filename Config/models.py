from django.db import models

# Create your models here.
class Application(models.Model):
    AppCSID=models.CharField(max_length=6)
    AppName=models.CharField(max_length=50)
    regionData=(('APAC','APAC'),('EMEA','EMEA'),('NAP','NAP'))
    AppRegion=models.CharField(max_length=4,choices=regionData,blank=True,help_text='Choose the Region',)
    AppCountries=models.TextField()
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
