from django.contrib import admin

# Register your models here.
from .models import Application,ServerConfig,ndmDetails

#admin.site.register(Application)
admin.site.register(ServerConfig)
admin.site.register(ndmDetails)

class AppAdmin(admin.ModelAdmin):
    list_display=('AppCSID','AppRegion','AppName','AppContacts')
    fields=[('AppCSID','AppRegion'),'AppName','AppCountries',('AppManager','AppContacts'),('AppSupportManager','AppSupportContacts'),('serviceNowL1L2','serviceNowL3'),'serviceNowBatch']
    
admin.site.register(Application,AppAdmin)