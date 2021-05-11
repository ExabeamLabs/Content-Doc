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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{1,100}[\w\-.]+\s{1,100}Skyformation""",
    """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
    """msg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """authenticationFailureMessage"{1,20}:"{1,20}({failure_reason}[^"]+)""",
    """userName":"(Invalid Authentication|({user_email}[^@"]+@[^"]+)|({user}[^"]+))""",
    """signonIPAddress"{1,20}:"{1,20}({dest_ip}[^"]+)""",
    """authenticationType"{1,20}:"{1,20}({auth_method}[^"]+)""",
    """dproc=({event_name}[^=]+?)\s{1,100}(\w+=|$)""",
    """requestClientApplication=({app}[^=]+?)\s{1,100}(\w+=|$)"""
  ]
}
```