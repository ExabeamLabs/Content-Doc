#### Parser Content
```Java
{
Name = s-xml-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-4771"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4771</EventID>", "<Data Name='TargetSid'>"]
  Fields = [
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<EventID>({event_code}[^<]+)</EventID>""",
    """<Data Name='TargetSid'>(?:NONE_MAPPED|({user_sid}[^<]+))</Data>""",
    """<Data Name='Status'>({result_code}[^<]+)</Data>""",
    """<Data Name='TargetUserName'>(?=\w)({user}[^<]+)</Data>""",
    """<Data Name='ServiceName'>\w+\/(?=\w)({domain}[^<]+)</Data>""",
    """<Data Name='IpAddress'>(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)</Data>""",
    """({event_name}Kerberos pre-authentication failed)""",
  ]
}
```