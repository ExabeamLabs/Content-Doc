#### Parser Content
```Java
{
Name = syslog-rsa-auth-failed
  DataType = "authentication-failed"
  Conditions = [ """ SINGLEPOINT """, """ USER_AUTHZ """, """RESULT="NOT_AUTHORIZED"""" ]

syslog-rsa-auth {
  Vendor = Dell
  Product = RSA Authentication Manager
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """({host}[\w\-.]{1,2000}) \d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) \S+ SINGLEPOINT""",
    """USERNAME="(unknown|({user}[^\s"]{1,2000}))""",
    """RESULT="({outcome}[^"]{1,2000})""",
    """authenticationType="?({auth_method}[^",]{1,2000})""",
    """UserAgent=({user_agent}[^"=,]{1,2000})""",
    """ipAddress=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """displayName =({user_lastname}[^=,]{1,2000}?),\s{0,100}({user_firstname}[^=,]{1,2000}?),""",
    """NameID=({name_id}[^,]{1,2000})""",
    """sAMAccountName =({sam_accountname}[^,]{1,2000})""",
    """POLICY="{0,20}({policy}[^"]{1,2000}?)\s{0,100}"""",
  
}
```