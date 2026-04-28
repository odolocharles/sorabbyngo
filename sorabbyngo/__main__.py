"""Entry point — run with: python -m sorabbyngo"""
from sorabbyngo.api.app import create_app

if __name__ == "__main__":
    app = create_app(dry_run=False)
    app.run(host="0.0.0.0", port=8000, debug=True)
