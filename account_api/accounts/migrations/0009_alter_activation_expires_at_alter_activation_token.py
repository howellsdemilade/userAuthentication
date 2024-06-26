# Generated by Django 5.0.3 on 2024-04-10 14:00

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0008_alter_activation_expires_at_alter_customuser_city_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='activation',
            name='expires_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 4, 30, 14, 0, 4, 807306, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='activation',
            name='token',
            field=models.CharField(max_length=70, null=True, unique=True),
        ),
    ]
