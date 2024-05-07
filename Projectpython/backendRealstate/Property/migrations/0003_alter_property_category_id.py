# Generated by Django 4.1.13 on 2024-02-28 18:00

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Property', '0002_category_property_category_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='property',
            name='category_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Property.category'),
        ),
    ]
