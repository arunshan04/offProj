# Generated by Django 3.0 on 2020-01-31 16:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Config', '0008_auto_20200131_1556'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='application',
            name='AppCountries',
        ),
        migrations.AddField(
            model_name='application',
            name='AppCountries',
            field=models.ManyToManyField(null=True, to='Config.Countries'),
        ),
    ]
