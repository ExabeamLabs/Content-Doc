#### Parser Content
```Java
{
Name = mcafee-siem-4779
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4779"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A session was disconnected from a Window Station.""" ]
    Fields = [
      """({event_name}A session was disconnected from a Window Station)""",
      """"src_ip":"({src_ip}[^"]{1,2000})""",
      """"dst_ip":"({dest_ip}[^"]{1,2000})""",
      """"id":\d{0,100}({event_code}4779)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]{1,2000})""",
      """"HostID":"({host}[^"]{1,2000})""",
      """"UserIDSrc":"({user}[^"]{1,2000})""",
      """"Source_Logon_ID":"({logon_id}[^"]{1,2000})""",
    ]
  

}
```