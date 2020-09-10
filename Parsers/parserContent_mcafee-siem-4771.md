#### Parser Content
```Java
{
Name = mcafee-siem-4771
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-4771"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """Kerberos pre-authentication failed""" ]
    Fields = [
      """({event_name}Kerberos pre-authentication failed)""",
      """"src_ip":"({src_ip}[^"]+)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d*({event_code}4771)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"Security_ID":"({user_sid}[^"]+)""",
      """"Service_Name":"({service_name}[^"]+)""",
      """"CommandID":"({result_code}[^"]+)""",
    ]
  }
```