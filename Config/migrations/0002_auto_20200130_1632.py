# Generated by Django 3.0 on 2020-01-30 16:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Config', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Application',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('AppCSID', models.CharField(max_length=6)),
                ('AppName', models.CharField(max_length=50)),
                ('AppRegion', models.CharField(blank=True, choices=[('APAC', 'APAC'), ('EMEA', 'EMEA'), ('NAP', 'NAP')], help_text='Choose the Region', max_length=4)),
                ('AppCountries', models.TextField()),
                ('AppContacts', models.CharField(max_length=500)),
                ('AppManager', models.CharField(max_length=500)),
                ('AppSupportContacts', models.CharField(max_length=500)),
                ('AppSupportManager', models.CharField(max_length=500)),
                ('serviceNowL1L2', models.CharField(max_length=500)),
                ('serviceNowL3', models.CharField(max_length=500)),
                ('serviceNowBatch', models.CharField(max_length=500)),
            ],
        ),
        migrations.DeleteModel(
            name='Applications',
        ),
    ]
