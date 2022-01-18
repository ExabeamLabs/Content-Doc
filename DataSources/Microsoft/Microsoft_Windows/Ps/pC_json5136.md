#### Parser Content
```Java
{
Name = json-5136
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-ds-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EventID":5136""", """A directory service object was modified""" ]
  Fields = [
    """"{1,20}EventTime"{1,20}:"{1,20}({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})"{1,20}"""
    """({event_name}A directory service object was modified)""",
    """"{1,20}Hostname"{1,20}:"{1,20}({host}[^"]{1,2000})"{1,20}""",
    """"{1,20}EventType"{1,20}:"{1,20}({outcome}[^"]{1,2000})"{1,20}""",
    """"{1,20}Severity"{1,20}:"{1,20}({severity_type}[^"]{1,2000})"{1,20}""",
    """"{1,20}EventID"{1,20}:({event_code}\d{1,100})""",
    """"{1,20}SourceName"{1,20}:"{1,20}({log_source}[^"]{1,2000})"{1,20}""",
    """""{1,20}ProviderGuid"{1,20}:"{1,20}\{({process_guid}[^}]{1,2000})""",
    """"{1,20}ActivityID"{1,20}:"{1,20}\{({activity_id}[^}]{1,2000})""",
    """"{1,20}ProcessID"{1,20}:({process_id}\d{1,100})"""
    """"{1,20}Message"{1,20}:"{1,20}({aditional_info}[^"]{1,2000})""",
    """"{1,20}Category"{1,20}:"{1,20}({category}[^"]{1,2000})"""
    """"SubjectUserName"{1,20}:"{1,20}({user}[^"]{1,2000})"""",    
    """"SubjectUserSid"{1,20}:"{1,20}({user_sid}[^"]{1,2000})"""",
    """"SubjectLogonId"{1,20}:"{1,20}({logon_id}[^"]{1,2000})"""",
    """"ObjectClass":"({object_class}[^"]{1,2000})"""",
    """"ObjectDN":"({object_dn}[^"]{1,2000})"""",
  ]
  DupFields = [ "host->dest_host" ]


}
```