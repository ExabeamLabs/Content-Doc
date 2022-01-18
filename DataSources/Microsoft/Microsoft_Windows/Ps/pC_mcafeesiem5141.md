#### Parser Content
```Java
{
Name = mcafee-siem-5141
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-ds-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A directory service object was deleted.""" ]
    Fields = [
      """({event_name}A directory service object was deleted)""",
      """"src_ip":"({src_ip}[^"]{1,2000})""",
      """"dst_ip":"({dest_ip}[^"]{1,2000})""",
      """"id":\d{0,100}({event_code}5141)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]{1,2000})""",
      """"HostID":"({host}[^"]{1,2000})""",
      """"UserIDSrc":"({user}[^"]{1,2000})""",
      """"Security_ID":"({user_sid}[^"]{1,2000})""",
      """"Source_Logon_ID":"({logon_id}[^"]{1,2000})""",
      """"ObjectID":"({object_dn}[^"]{1,2000})""",
      """"ObjectID":"[^"]{0,2000}?({object_ou}(OU|ou)[^"]{1,2000})""",
      """"Target_Class":"({object_class}[^"]{1,2000})""",
      """"Process_Name":"({process_name}[^"]{1,2000})""",
    ]
    DupFields = [ "host->dest_host" ]
  

}
```