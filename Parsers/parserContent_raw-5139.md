#### Parser Content
```Java
{
Name = raw-5139
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-ds-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Directory Service:""", """Object:""", """Old DN:""", """New DN:""", """A directory service object was moved"""]
  Fields = [
    """({event_name}A directory service object was moved)""",
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+Microsoft-Windows-Security-Auditing""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Security ID:\s+({user_sid}[^\s]+?)\s+Account Name:\s+({user}[^\s]+?)\s+Account Domain:\s+((?i)(NA)|({domain}[^\s]+?))\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """Class:\s+({object_class}[^:]+?)\s+Operation:""",
    """Object:[^\{\}]+?New DN:\s+({object_dn}[^\s]+)""",
    """Object:\s+Old DN:[^\{\}]+?({object_ou}OU[^\s]+?)\s+GUID:""",
    """Directory Service:\s*Name:\s*({service_name}[^\s]+)\s+Type:\s*({service_type}[^:]*?Services)""",
    """GUID:\s*\{({guid}[^\}]+)""",
    """Operation:\s*Correlation ID:\s*\{({correlation_id}[^\}]+)""",	
    ]
  DupFields = [ "host->dest_host" ]
}
```