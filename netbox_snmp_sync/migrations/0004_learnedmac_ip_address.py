from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_snmp_sync", "0003_learnedmac_ephemeral_device_id"),
    ]

    operations = [
        migrations.AddField(
            model_name="learnedmac",
            name="ip_address",
            field=models.GenericIPAddressField(blank=True, db_index=True, null=True),
        ),
    ]
