from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_snmp_sync", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="LearnedMAC",
            fields=[
                ("id",                   models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("mac_address",          models.CharField(db_index=True, max_length=17)),
                ("vendor",               models.CharField(blank=True, max_length=200)),
                ("source_device_ip",     models.GenericIPAddressField(db_index=True)),
                ("source_device_name",   models.CharField(blank=True, max_length=200)),
                ("source_interface",     models.CharField(blank=True, max_length=100)),
                ("vlan",                 models.PositiveSmallIntegerField(default=0)),
                ("entry_type",           models.CharField(db_index=True, default="learned", max_length=10,
                                                          choices=[("learned","Learned"),("self","Self"),("mgmt","Mgmt"),("other","Other")])),
                ("status",               models.CharField(db_index=True, default="new", max_length=10,
                                                          choices=[("new","New"),("active","Active"),("stale","Stale"),("promoted","Promoted")])),
                ("first_seen",           models.DateTimeField(auto_now_add=True, db_index=True)),
                ("last_seen",            models.DateTimeField(default=django.utils.timezone.now, db_index=True)),
                ("promoted_to_device_id", models.PositiveIntegerField(blank=True, null=True)),
                ("promoted_at",          models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "verbose_name": "Learned MAC",
                "verbose_name_plural": "Learned MACs",
                "ordering": ["-last_seen"],
            },
        ),
        migrations.AddConstraint(
            model_name="learnedmac",
            constraint=models.UniqueConstraint(
                fields=["mac_address", "source_device_ip"],
                name="unique_mac_per_device",
            ),
        ),
        migrations.CreateModel(
            name="OUIDatabase",
            fields=[
                ("id",              models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("registry",        models.CharField(db_index=True, max_length=10, unique=True,
                                                     choices=[("MA-L","MA-L (24-bit, ~37k entries)"),("MA-M","MA-M (28-bit)"),("MA-S","MA-S (36-bit)")])),
                ("local_path",      models.CharField(blank=True, max_length=500)),
                ("last_downloaded", models.DateTimeField(blank=True, null=True)),
                ("entry_count",     models.PositiveIntegerField(default=0)),
                ("last_error",      models.TextField(blank=True)),
            ],
            options={"verbose_name": "OUI Database", "verbose_name_plural": "OUI Databases", "ordering": ["registry"]},
        ),
        migrations.CreateModel(
            name="SyncSchedule",
            fields=[
                ("id",              models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("enabled",         models.BooleanField(default=False)),
                ("cron_expression", models.CharField(blank=True, default="0 2 * * *", max_length=100)),
                ("seed_ips",        models.TextField(blank=True)),
                ("max_depth",       models.PositiveSmallIntegerField(default=2)),
                ("max_workers",     models.PositiveSmallIntegerField(default=8)),
                ("last_run_at",     models.DateTimeField(blank=True, null=True)),
                ("last_run_status", models.CharField(blank=True, max_length=20)),
            ],
            options={"verbose_name": "Sync Schedule", "verbose_name_plural": "Sync Schedule"},
        ),
    ]
