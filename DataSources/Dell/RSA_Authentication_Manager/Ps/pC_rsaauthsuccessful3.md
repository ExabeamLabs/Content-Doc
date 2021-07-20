#### Parser Content
```Java
{
Name = rsa-auth-successful-3
  Vendor = Dell
  Product = RSA Authentication Manager
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ SINGLEPOINT """, """ USER_STEPUP_AUTHN """, """REQUEST_CONTEXT_ID="""" ]
  Fields = [
    """({host}[\w\-.]{1,2000}) \d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) \S+ SINGLEPOINT""",
    """USERNAME="({user}[^\s"]{1,2000})""",
    """APP_NAME="({app}[^"]{1,2000})""",
    """SENSITIVITY_LEVEL="({sensitivity_level}[^"]{1,2000})""",
    """TENANT="({tenant}[^"]{1,2000})""",
    """REQUEST_CONTEXT_ID="({context_id}[^"]{1,2000})""",
    """RESULT="({outcome}[^"]{1,2000})""",
  ]
}
```