# Generated by Django 3.2.8 on 2021-10-28 14:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_auto_20211028_0257'),
    ]

    operations = [
        migrations.AddField(
            model_name='transaction',
            name='transactionNo',
            field=models.CharField(default=1, max_length=32, unique=True),
            preserve_default=False,
        ),
    ]
