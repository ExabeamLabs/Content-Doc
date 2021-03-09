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
    """"+EventTime"+:"+({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})"+"""
    """({event_name}A directory service object was modified)""",
    """"+Hostname"+:"+({host}[^"]+)"+""",
    """"+EventType"+:"+({outcome}[^"]+)"+""",
    """"+Severity"+:"+({severity_type}[^"]+)"+""",
    """"+EventID"+:({event_code}\d+)""",
    """"+SourceName"+:"+({log_source}[^"]+)"+""",
    """""+ProviderGuid"+:"+\{({process_guid}[^}]+)""",
    """"+ActivityID"+:"+\{({activity_id}[^}]+)""",
    """"+ProcessID"+:({process_id}\d+)"""
    """"+Message"+:"+({aditional_info}[^"]+)""",
    """"+Category"+:"+({category}[^"]+)"""
    """"SubjectUserName"+:"+({user}[^"]+)"""",    
    """"SubjectUserSid"+:"+({user_sid}[^"]+)"""",
    """"SubjectLogonId"+:"+({logon_id}[^"]+)"""",
    """"ObjectClass":"({object_class}[^"]+)"""",
    """"ObjectDN":"({object_dn}[^"]+)"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```