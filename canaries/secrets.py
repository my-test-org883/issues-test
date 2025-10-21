# Multiple secret vulnerabilities for testing scanners

# Vulnerability #1: GitHub Personal Access Token
GITHUB_TOKEN = "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"

# Vulnerability #2: Stripe Live API Key
STRIPE_KEY = "sk_live_A7jK4iCYHL045qgjjfzAfPxu"

# Vulnerability #3: JWT Token
JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"

# Vulnerability #4: AWS Access Keys
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Vulnerability #5: Slack Bot Token
SLACK_TOKEN = os.environ.get("SLACK_TOKEN")

# Vulnerability #6: Google API Key
GOOGLE_API_KEY = "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"

# Vulnerability #7: Database connection with credentials
DATABASE_URL = "postgresql://admin:password123@db.example.com:5432/myapp"

# Vulnerability #8: MongoDB connection string
MONGO_URI = "mongodb://root:secret123@mongo.example.com:27017/admin"

# Vulnerability #9: Docker registry token
DOCKER_TOKEN = "dckr_pat_1234567890abcdefghijklmnopqrstuvwxyz"

# Vulnerability #10: SendGrid API Key
SENDGRID_API_KEY = "SG.1234567890abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz1234567890"

call_some_api(GITHUB_TOKEN)
call_other_api(STRIPE_KEY)
call_more_api(JWT_TOKEN)
