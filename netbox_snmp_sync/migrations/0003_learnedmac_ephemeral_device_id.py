from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_snmp_sync", "0002_learned_mac_oui_schedule"),
    ]

    operations = [
        migrations.AddField(
            model_name="learnedmac",
            name="ephemeral_device_id",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]
