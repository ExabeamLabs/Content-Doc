#### Parser Content
```Java
{
Name = mcafee-siem-4771
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4771"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """Kerberos pre-authentication failed""" ]
    Fields = [
      """({event_name}Kerberos pre-authentication failed)""",
      """"src_ip":"({src_ip}[^"]{1,2000})""",
      """"dst_ip":"({dest_ip}[^"]{1,2000})""",
      """"id":\d{0,100}({event_code}4771)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]{1,2000})""",
      """"HostID":"({host}[^"]{1,2000})""",
      """"UserIDSrc":"({user}[^"]{1,2000})""",
      """"Security_ID":"({user_sid}[^"]{1,2000})""",
      """"Service_Name":"({service_name}[^"]{1,2000})""",
      """"CommandID":"({result_code}[^"]{1,2000})""",
    ]
    DupFields = ["host->dest_host"]
  

}
```