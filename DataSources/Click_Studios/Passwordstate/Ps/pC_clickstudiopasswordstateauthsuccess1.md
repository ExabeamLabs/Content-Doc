#### Parser Content
```Java
{
Name = clickstudio-passwordstate-auth-success-1
  Vendor = Click Studios
  Product = Passwordstate
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "dd-mm-yyy HH:mm:ss"
  Conditions = [ """Passwordstate:""", """Successful""", """login for UserID"""]
  Fields = [
    """({time}\d{2}-\d{2}-\d{4}\s\d{2}:\d{2}:\d{2})\s""",
    """IP Address\s{1,100}=\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Passwordstate:\s{1,100}({outcome}Successful)\s""",
    """({event_name}Successful 'SAML' login for UserID)""",
    """\d\d:\d\d:\d\d\s({host}[\w\-.]{1,2000})\s{1,100}""",
    """UserID\s{1,20}'(({domain}[^']{1,2000})\\)?({user}[^']{1,2000})"""
  ]


}
```