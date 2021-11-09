#### Parser Content
```Java
{
Name = mcafee-siem-4726
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-account-deleted"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A user account was deleted.""" ]
    Fields = [
      """({event_name}A user account was deleted)""",
      """"src_ip":"({src_ip}[^"]{1,2000})""",
      """"dst_ip":"({dest_ip}[^"]{1,2000})""",
      """"id":\d{0,100}({event_code}4726)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]{1,2000})""",
      """"HostID":"({host}[^"]{1,2000})""",
      """"UserIDSrc":"({user}[^"]{1,2000})""",
      """"Security_ID":"({user_sid}[^"]{1,2000})""",
      """"Source_Logon_ID":"({logon_id}[^"]{1,2000})""",
      """"UserIDDst":"({target_user}[^"]{1,2000})"""
    ]
    DupFields = [ "host->dest_host", "target_user->account_name" ]
  }
}
```