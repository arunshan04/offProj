# Generated by Django 3.0 on 2020-01-31 15:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Config', '0004_ndmdetails'),
    ]

    operations = [
        migrations.CreateModel(
            name='Choices',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.CharField(max_length=300)),
            ],
        ),
        migrations.AddField(
            model_name='application',
            name='choices',
            field=models.ManyToManyField(to='Config.Choices'),
        ),
    ]
