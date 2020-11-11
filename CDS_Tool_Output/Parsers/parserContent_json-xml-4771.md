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
    """"Activity":"({event_name}[^"]+)""",
    """"Computer":"({host}[^"]+)""",
    """<Data Name='TargetSid'>(?:NONE_MAPPED|({user_sid}[^<]+))</Data>""",
    """<Data Name='Status'>({result_code}[^<]+)</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({user}[^<]+)</Data>""",
    """<Data Name='ServiceName'>\w+\/(?=\w)({domain}[^<]+)</Data>""",
    """<Data Name='IpAddress'>(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)</Data>"""
  ]
}
```