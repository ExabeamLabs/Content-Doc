#### Parser Content
```Java
{
Name = json-xml-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4771"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ ""","EventID":"4771",""", """<Data Name='TargetSid'>""", """Kerberos pre-authentication failed""" ]
  Fields = [
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({event_code}4771)""",
    """"Activity":"({event_name}[^"]{1,2000})""",
    """"Computer":"({host}[^"]{1,2000})""",
    """<Data Name='TargetSid'>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))</Data>""",
    """<Data Name='Status'>({result_code}[^<]{1,2000})</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({user}[^<]{1,2000})</Data>""",
    """<Data Name='ServiceName'>\w+\/(?=\w)({domain}[^<]{1,2000})</Data>""",
    """<Data Name='IpAddress'>(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})</Data>"""
  ]
  DupFields = ["host->dest_host"]
}
```