#### Parser Content
```Java
{
Name = sk4-workday-app-auth-failed
  Vendor = Workday
  Product = Workday
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """|security-threat-detected|""", """cat=security-alert""", """destinationServiceName=Workday""", """authenticationFailureMessage"""]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{1,100}[\w\-.]{1,2000}\s{1,100}Skyformation""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """msg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """authenticationFailureMessage"{1,20}:"{1,20}({failure_reason}[^"]{1,2000})""",
    """userName":"(Invalid Authentication|({user_email}[^@"]{1,2000}@[^"]{1,2000})|({user}[^"]{1,2000}))""",
    """signonIPAddress"{1,20}:"{1,20}({dest_ip}[^"]{1,2000})""",
    """authenticationType"{1,20}:"{1,20}({auth_method}[^"]{1,2000})""",
    """dproc=({event_name}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """requestClientApplication=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)"""
  ]
}
```