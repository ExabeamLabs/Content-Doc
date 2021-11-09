#### Parser Content
```Java
{
Name = rsa-failed-app-login
  DataType = "failed-app-login"
  Conditions = [ """ SINGLEPOINT """, """ USER_LOGIN """, """RESULT="NOT_AUTHENTICATED"""" ]
}
rsa-app-login = {
  Vendor = Dell
  Product = RSA Authentication Manager
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ SINGLEPOINT """, """ USER_PROTECTED_APP_AUTHN """ ]
  Fields = [
    """({host}[\w\-.]{1,2000}) \d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) \S+ SINGLEPOINT""",
    """USERNAME="(unknown|({user}[^\s"]{1,2000}))""",
    """RESULT="({outcome}[^"]{1,2000})""",
    """APPLICATION="({app}[^"]{1,2000})""",
    """TYPE="({auth_method}[^"]{1,2000})""",
    """SESSION_ID="({session_id}[^"]{1,2000})""",
    """NOT_AUTHNED_REASON="({failure_reason}[^"]{1,2000})""",
  ]}
```