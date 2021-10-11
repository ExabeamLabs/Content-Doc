#### Parser Content
```Java
{
Name = pan-azure-auth-successful
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,SYSTEM,auth,""", """AUTH_PROFILE_AZURE""", """,saml-signature-validated,""" ]
  Fields = [
    """\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\d{1,100},({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}),""",
    """(c|C)lient '({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """for user\s{0,100}'({user_email}[^']{1,2000})""" 
    ]
}
```