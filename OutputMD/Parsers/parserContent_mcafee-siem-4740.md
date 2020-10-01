#### Parser Content
```Java
{
Name = mcafee-siem-4740
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-lockout"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A user account was locked out.""" ]
    Fields = [
      """({event_name}A user account was locked out)""",
      """"src_ip":"({src_ip}[^"]+)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d*({event_code}4740)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({caller_domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({caller_user}[^"]+)""",
      """"Security_ID":"({user_sid}[^"]+)""",
      """"Source_Logon_ID":"({logon_id}[^"]+)""",
      """"UserIDDst":"({user}[^"]+)"""
    ]
    DupFields = [ "host->dest_host", "caller_domain->domain" ]
  }
```