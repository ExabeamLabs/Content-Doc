#### Parser Content
```Java
{
Name = mcafee-siem-4648
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-account-switch"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A logon was attempted using explicit credentials.""" ]
    Fields = [
      """({event_name}A logon was attempted using explicit credentials)""",
      """"src_ip":"({src_ip}[^"]{1,2000})""",
      """"dst_ip":"({dest_ip}[^"]{1,2000})""",
      """"id":\d{0,100}({event_code}4648)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]{1,2000})""",
      """"HostID":"({host}[^"]{1,2000})""",
      """"UserIDSrc":"({user}[^"]{1,2000})""",
      """"UserIDDst":"({account}[^"]{1,2000})""",
      """"Security_ID":"({user_sid}[^"]{1,2000})""",
      """"Source_Logon_ID":"({logon_id}[^"]{1,2000})""",
      """"Process_Name":"({process_name}[^"]{1,2000}?)"""",
      """"PID":"({process_id}[^"]{1,2000})""",
    ]
  

}
```