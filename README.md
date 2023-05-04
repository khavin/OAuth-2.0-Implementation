# OAuth-2.0-Implementation

# Installation instructions
Install Python version 3.8.10 from python.org
Install MongoDB version 6.0.5 from https://www.mongodb.com
Next, install the required python libraries.

```bash
pip install -r /path/to/requirements.txt
```

# Setup MongoDB
Start the mongodb service on your system. 

Create a db named 'resourceServerDB'
```bash
use resourceServerDB
```

# Start all the services

Start the client server backend service
```bash
uvicorn main:app --reload --port 8080
```

Start the client server frontend service
```bash
uvicorn main:app --reload --port 7000
```

Start the authorization server backend service
```bash
uvicorn main:app --reload --port 8000
```

Start the authorization server frontend service
```bash
uvicorn main:app --reload --port 7001
```

Start the resource server backend service
```bash
uvicorn main:app --reload --port 8090
```
If you would like to the services on a different port, then make the changes in code accordingly.


