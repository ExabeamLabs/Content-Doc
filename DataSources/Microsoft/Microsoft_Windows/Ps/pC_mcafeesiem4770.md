#### Parser Content
```Java
{
Name = mcafee-siem-4770
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4770"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A Kerberos service ticket was renewed""" ]
    Fields = [
      """({event_name}A Kerberos service ticket was renewed)""",
      """"dst_ip":"({src_ip}[^"]{1,2000})""",
      """"id":\d{0,100}({event_code}4770)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]{1,2000})""",
      """"HostID":"({host}[^"]{1,2000})""",
      """"UserIDSrc":"({user}[^"]{1,2000})""",
      """"Service_Name":"({service_name}[^"]{1,2000})""",
      """"Service_Name":"({dest_host}[^"]{1,2000}\$)""",
      """({event_code}4770)"""
    ]
  

}
```