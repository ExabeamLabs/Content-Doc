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
      """"src_ip":"({src_ip}[^"]+)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d*({event_code}5141)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"Security_ID":"({user_sid}[^"]+)""",
      """"Source_Logon_ID":"({logon_id}[^"]+)""",
      """"ObjectID":"({object_dn}[^"]+)""",
      """"ObjectID":"[^"]*?({object_ou}(OU|ou)[^"]+)""",
      """"Target_Class":"({object_class}[^"]+)""",
      """"Process_Name":"({process_name}[^"]+)""",
    ]
    DupFields = [ "host->dest_host" ]
  }
```