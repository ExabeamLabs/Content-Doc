#### Parser Content
```Java
{
Name = json-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "epoch_sec"
    Conditions = ["""4768""", """"ServiceName":"""", """Pre-Authentication"""]
    Fields = [
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s*({time}\d+)""",
      """"timestamp":\s*({time}\d+)""",
      """"(Hostname|MachineName)":"({host}[^"]*)""",
      """({event_code}4768)""",
      """"(TargetUserName|AccountName)":"({user}[^"]+)""",
      """"(TargetDomainName|SuppliedRealmName)":"({domain}[^."]+)""",
      """"(UserID|TargetSid)":"({user_sid}[^"]+)""",
      """"(IpAddress|ClientAddress)":"(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
      """"(Status|ResultCode)":"({result_code}[^"]+)"""
    ]
  }
```