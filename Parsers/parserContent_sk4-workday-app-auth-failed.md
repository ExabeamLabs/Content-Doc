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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d+Z\s+[\w\-.]+\s+Skyformation""",
    """msg=({additional_info}.+?)\s+(\w+=|$)""",
    """authenticationFailureMessage"+:"+({failure_reason}[^"]+)""",
    """userName"+:"+(Invalid Authentication|({user}[^"]+))""",
    """signonIPAddress"+:"+({dest_ip}[^"]+)""",
    """authenticationType"+:"+({auth_method}[^"]+)""",
    """dproc=({event_name}.+?)\s+(\w+=|$)""",
    """requestClientApplication=({app}.+?)\s+(\w+=|$)""",
  ]
}
```