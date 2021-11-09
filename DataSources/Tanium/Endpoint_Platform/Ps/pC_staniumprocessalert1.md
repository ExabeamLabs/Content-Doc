#### Parser Content
```Java
{
Name = s-tanium-process-alert-1
  Vendor = Tanium
  Product = Endpoint Platform
  Lms = Default
  DataType = "process-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Computer Name""", """Computer IP""", """Intel Type""", """Reputation Malicious Files""", """md5"""  ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """Timestamp"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """Alert Id"{1,20}:"{1,20}({alert_id}[^"]{1,2000})""",
    """Computer Name"{1,20}:"{1,20}({source_host}[^".]{1,2000})""",
    """Computer IP"{1,20}:"{1,20}({source_ip}[A-Za-z0-9.:]{1,2000})""",
    """({alert_name}Reputation Malicious Files)""",
    """Intel Type"{1,20}:"{1,20}({alert_type}[^"]{1,2000})""",
    """properties"{1,20}:[^\]]{1,2000}?fullpath"{1,20}:"{1,20}({process}({process_directory}[^"]{1,2000})\\+({process_name}[^"]{1,2000}))""",
    """md5"{1,20}:"{1,20}({md5}[^"]{1,2000})""",
    """os"{1,20}:"{1,20}({os}[^"]{1,2000})""",
    """suser=(anonymous|({user}[^\s]{1,2000}))""",
    """({app}Tanium)"""
    ]
}
}
```