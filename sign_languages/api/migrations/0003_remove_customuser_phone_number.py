# Generated by Django 5.0.1 on 2024-01-28 18:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0002_customuser_phone_number"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="customuser",
            name="phone_number",
        ),
    ]