#!/bin/bash

echo "======================================"
echo "Insider Threat Detection System Setup"
echo "======================================"
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $python_version"
echo ""

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create directories
echo "Creating data directories..."
mkdir -p data/raw data/processed data/models logs

# Initialize database
echo ""
echo "Initializing database..."
python3 <<EOF
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
    print("✓ Database initialized!")
EOF

echo ""
echo "======================================"
echo "Setup Complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "1. Train model on Google Colab using CERT_Training_Colab.ipynb"
echo "2. Download model files to data/models/"
echo "3. Import user profiles"
echo "4. Run: python run.py"
echo ""
echo "Default login:"
echo "Username: admin"
echo "Password: printed once in the console the first time the app starts"
echo ""
echo "⚠️  IMPORTANT: Change password after first login!"
echo ""
