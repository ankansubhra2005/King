recon_platform/
├── app/
│   ├── api/
│   │   ├── __init__.py
│   │   ├── router.py
│   │   └── endpoints/
│   │       ├── __init__.py
│   │       ├── targets.py
│   │       └── scans.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── input_layer.py
│   │   ├── recon_engine.py
│   │   ├── crawler.py
│   │   ├── js_engine.py
│   │   └── secret_engine.py
│   ├── db/
│   │   ├── __init__.py
│   │   └── session.py
│   ├── models/
│   │   ├── __init__.py
│   │   └── models.py
│   ├── workers/
│   │   ├── __init__.py
│   │   ├── celery_app.py
│   │   └── tasks.py
│   └── main.py
├── cli/
│   ├── __init__.py
│   └── main.py
├── migrations/
├── tests/
│   ├── __init__.py
│   └── test_input_layer.py
├── wordlists/
│   ├── subdomain_wordlist.txt
│   └── directory_wordlist.txt
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
