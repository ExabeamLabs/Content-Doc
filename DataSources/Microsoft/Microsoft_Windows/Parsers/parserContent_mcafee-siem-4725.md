#### Parser Content
```Java
{
Name = mcafee-siem-4725
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-disabled"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A user account was disabled.""" ]
    Fields = [
      """({event_name}A user account was disabled)""",
      """"src_ip":"({src_ip}[^"]+)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d*({event_code}4725)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"Security_ID":"({user_sid}[^"]+)""",
      """"Source_Logon_ID":"({logon_id}[^"]+)""",
      """"UserIDDst":"({target_user}[^"]+)"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```