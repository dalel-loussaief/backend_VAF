# Generated by Django 4.1.13 on 2024-04-18 14:41

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('userAuth', '0018_category_service_property_image'),
    ]

    operations = [
        migrations.CreateModel(
            name='PropertyInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('property_titre', models.CharField(max_length=255)),
                ('property_description', models.TextField()),
                ('property_surface', models.IntegerField()),
                ('property_dispo', models.CharField(max_length=255)),
                ('property_prix', models.IntegerField()),
                ('image', models.ImageField(default='default_image.jpg', upload_to='property_images/')),
                ('owner_email', models.EmailField(max_length=254)),
                ('category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='userAuth.category')),
                ('service', models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='userAuth.service')),
            ],
        ),
    ]
