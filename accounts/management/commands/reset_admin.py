from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model


class Command(BaseCommand):
    help = 'Reset admin password to Admin@2025'

    def handle(self, *args, **options):
        User = get_user_model()
        
        try:
            admin = User.objects.get(username='admin')
            admin.set_password('Admin@2025')
            admin.save()
            self.stdout.write(self.style.SUCCESS('✓ Admin password reset successfully to: Admin@2025'))
        except User.DoesNotExist:
            # Create admin if doesn't exist
            admin = User.objects.create_superuser(
                username='admin',
                email='admin@phishguard.local',
                password='Admin@2025'
            )
            self.stdout.write(self.style.SUCCESS('✓ Admin user created with password: Admin@2025'))
