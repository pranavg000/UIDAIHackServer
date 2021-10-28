# Generated by Django 3.2.8 on 2021-10-28 15:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_auto_20211028_0257'),
    ]

    operations = [
        migrations.CreateModel(
            name='OfflineEKYC',
            fields=[
                ('transactionId', models.CharField(max_length=64, primary_key=True, serialize=False)),
                ('encryptedEKYC', models.TextField()),
                ('encryptedPasscode', models.TextField()),
                ('filename', models.CharField(max_length=50)),
            ],
        ),
    ]
