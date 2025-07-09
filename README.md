# Credential Manager
This is a simple credential manager written in Python. Using `credential_manager.py` you can use basic CRUD operations on an encrypted credential store. If no store is found, it will create one for you.

Of note, to create new credentials, you will be prompted "Enter credential key to add/update". This will be the name of the credential you are saving. For instance 'db-user'. After this, you will be prompted: "Enter value for xxxx" where 'xxxx' is the key that you just entered previously. THIS is where your credential will be. As an example: 
```
Enter credential key to add/update: DB-USER
Enter value for 'DB-USER': database_user
Enter credential key to add/update: DB-PASS
Enter value for 'DB-PASS": databse_password
Enter credential key to add/update:
```
When you are done editing or adding credentials, press 'Enter' on a blank line to store the credentials. The script will auto-save into the store. By default, this store is located in `credentials.enc` in the same file location as where it was created.

View the `example_usage.py` script to see an example of how to actually use these credentials programmatically.
