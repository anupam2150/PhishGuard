#!/usr/bin/env bash
set -e

# WeasyPrint system dependencies
apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

pip install -r requirements.txt
