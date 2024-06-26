# Generated by Django 4.1.13 on 2024-04-27 15:21

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('userAuth', '0024_alter_localisation_emplacement'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='propertyinfo',
            name='property_location',
        ),
        migrations.AddField(
            model_name='propertyinfo',
            name='localisation',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='userAuth.localisation'),
        ),
        migrations.AlterField(
            model_name='localisation',
            name='emplacement',
            field=models.CharField(max_length=255),
        ),
    ]
