from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True
    dependencies = []

    operations = [
        migrations.CreateModel(
            name="SyncLog",
            fields=[
                ("id",            models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("started_at",    models.DateTimeField(auto_now_add=True, db_index=True)),
                ("completed_at",  models.DateTimeField(blank=True, null=True)),
                ("status",        models.CharField(db_index=True, default="pending", max_length=20,
                                                   choices=[("pending","Pending"),("running","Running"),("success","Success"),("failed","Failed")])),
                ("message",           models.TextField(blank=True)),
                ("devices_seen",      models.PositiveIntegerField(default=0)),
                ("devices_created",   models.PositiveIntegerField(default=0)),
                ("devices_updated",   models.PositiveIntegerField(default=0)),
                ("interfaces_synced", models.PositiveIntegerField(default=0)),
                ("macs_synced",       models.PositiveIntegerField(default=0)),
            ],
            options={"verbose_name": "Sync Log", "verbose_name_plural": "Sync Logs", "ordering": ["-started_at"]},
        ),
        migrations.CreateModel(
            name="SNMPCredential",
            fields=[
                ("id",            models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name",          models.CharField(max_length=100, unique=True)),
                ("priority",      models.PositiveSmallIntegerField(default=10)),
                ("version",       models.CharField(max_length=2, default="2",
                                                   choices=[("2","SNMPv2c"),("3","SNMPv3")])),
                ("community",     models.CharField(blank=True, max_length=200)),
                ("username",      models.CharField(blank=True, max_length=200)),
                ("auth_protocol", models.CharField(blank=True, max_length=10,
                                                   choices=[("MD5","MD5"),("SHA","SHA"),("SHA224","SHA-224"),
                                                            ("SHA256","SHA-256"),("SHA384","SHA-384"),("SHA512","SHA-512")])),
                ("auth_key",      models.CharField(blank=True, max_length=200)),
                ("priv_protocol", models.CharField(blank=True, max_length=10,
                                                   choices=[("DES","DES"),("AES","AES-128"),("AES192","AES-192"),("AES256","AES-256")])),
                ("priv_key",      models.CharField(blank=True, max_length=200)),
            ],
            options={"verbose_name": "SNMP Credential", "verbose_name_plural": "SNMP Credentials", "ordering": ["priority", "name"]},
        ),
    ]
