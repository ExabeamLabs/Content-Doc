#### Parser Content
```Java
{
Name = mcafee-siem-4720
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-account-created"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A user account was created""" ]
    Fields = [
      """({event_name}A user account was created)""",
      """"src_ip":"({src_ip}[^"]+)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d*({event_code}4720)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"Security_ID":"({user_sid}[^"]+)""",
      """"Source_Logon_ID":"({logon_id}[^"]+)""",
      """"UserIDDst":"({account_name}[^"]+)""",
      """"Event_Class":"({additional_info}[^"]+)"""
    ]
  }
```