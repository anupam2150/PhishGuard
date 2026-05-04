import os
from django.core.management import execute_from_command_line
from dotenv import load_dotenv

load_dotenv()
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "phishguard.settings")

if __name__ == "__main__":
    execute_from_command_line()
