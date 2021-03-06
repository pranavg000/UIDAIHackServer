# Generated by Django 3.2.8 on 2021-10-26 15:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AnonProfile',
            fields=[
                ('userUIDToken', models.CharField(max_length=30, primary_key=True, serialize=False)),
                ('authToken', models.CharField(max_length=256)),
                ('deviceID', models.CharField(max_length=256)),
                ('publicKey', models.CharField(max_length=1024)),
                ('shareableCode', models.CharField(max_length=1024)),
            ],
        ),
        migrations.CreateModel(
            name='Ekyc',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ekycFile', models.FileField(upload_to='')),
                ('encPassCode', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='Transaction',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('state', models.CharField(choices=[('init', 'Initiated by requester'), ('accepted', 'Lender ready to share'), ('rejected', 'Lender rejects request'), ('shared', 'ekyc shared with requester'), ('aborted', 'Aborted due to any reason'), ('commited', 'Address updated successfully')], default='init', max_length=10)),
                ('lender', models.ForeignKey(on_delete=django.db.models.deletion.RESTRICT, related_name='lender', to='core.anonprofile')),
                ('requester', models.ForeignKey(on_delete=django.db.models.deletion.RESTRICT, related_name='requester', to='core.anonprofile')),
            ],
        ),
        migrations.CreateModel(
            name='Notifications',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('messageHeading', models.CharField(max_length=64)),
                ('messageBody', models.CharField(max_length=512)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('receiver', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notifReceiver', to='core.anonprofile')),
            ],
        ),
    ]
