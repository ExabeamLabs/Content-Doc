#### Parser Content
```Java
{
Name = s-xml-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-4771"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "<EventID>4771</EventID>", "<Data Name ='TargetSid'>"]
  Fields = [
    """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """<EventID>({event_code}[^<]{1,2000})</EventID>""",
    """<Data Name ='TargetSid'>(?:NONE_MAPPED|({user_sid}[^<]{1,2000}))</Data>""",
    """<Data Name ='Status'>({result_code}[^<]{1,2000})</Data>""",
    """<Data Name ='TargetUserName'>(?=\w)({user}[^<]{1,2000})</Data>""",
    """<Data Name ='ServiceName'>\w+\/(?=\w)({domain}[^<]{1,2000})</Data>""",
    """<Data Name ='IpAddress'>(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})</Data>""",
    """({event_name}Kerberos pre-authentication failed)""",
  ]


}
```