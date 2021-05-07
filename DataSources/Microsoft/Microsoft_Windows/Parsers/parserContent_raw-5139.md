#### Parser Content
```Java
{
Name = raw-5139
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-ds-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """Directory Service:""", """Object:""", """Old DN:""", """New DN:""", """A directory service object was moved"""]
  Fields = [
    """({event_name}A directory service object was moved)""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s{1,100}(Microsoft-Windows-Security-Auditing|MSWinEventLog)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s({time}\w+\s\d\d\s\d\d:\d\d:\d\d\s\d{4})\s""",
    """Security ID:\s{1,100}({user_sid}[^\s]+?)\s{1,100}Account Name:\s{1,100}({user}[^\s]+?)\s{1,100}Account Domain:\s{1,100}((?i)(NA)|({domain}[^\s]+?))\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]+)""",
    """Class:\s{1,100}({object_class}[^:]+?)\s{1,100}Operation:""",
    """Object:[^\{\}]+?New DN:\s{1,100}({object_dn}[^:]+?)\s{1,100}GUID:""",
    """Object:\s{1,100}Old DN:[^\{\}]+?({object_ou}OU[^:]+?)\s{1,100}GUID:""",
    """Directory Service:\s{0,100}Name:\s{0,100}({service_name}[^\s]+)\s{1,100}Type:\s{0,100}({service_type}[^:]*?Services)""",
    """GUID:\s{0,100}\{({guid}[^\}]+)""",
    """Operation:\s{0,100}Correlation ID:\s{0,100}\{({correlation_id}[^\}]+)""",
    """Object:\s{1,100}Old DN:[^\{\}]+?\s{0,100}({old_attribute}[^:]+?)\s{1,100}New DN:\s{0,100}({new_attribute}[^:]+?)\s{1,100}GUID:""",
    """({event_code}5139)"""
    ]
  DupFields = [ "host->dest_host" ]
}
```