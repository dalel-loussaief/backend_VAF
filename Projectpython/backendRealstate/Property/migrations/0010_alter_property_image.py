# Generated by Django 4.1.13 on 2024-03-22 23:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Property', '0009_property_image'),
    ]

    operations = [
        migrations.AlterField(
            model_name='property',
            name='image',
            field=models.ImageField(default='', upload_to='property_images/'),
        ),
    ]
