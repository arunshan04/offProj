# Generated by Django 3.0 on 2020-01-30 17:08

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Config', '0003_serverconfig'),
    ]

    operations = [
        migrations.CreateModel(
            name='ndmDetails',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('NodeName', models.CharField(max_length=40)),
                ('LogDir', models.CharField(max_length=200)),
                ('Server', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='Config.ServerConfig')),
            ],
        ),
    ]
