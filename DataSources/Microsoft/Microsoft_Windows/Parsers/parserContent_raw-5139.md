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
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}Microsoft-Windows-Security-Auditing""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Security ID:\s{1,100}({user_sid}[^\s]{1,2000}?)\s{1,100}Account Name:\s{1,100}({user}[^\s]{1,2000}?)\s{1,100}Account Domain:\s{1,100}((?i)(NA)|({domain}[^\s]{1,2000}?))\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Class:\s{1,100}({object_class}[^:]{1,2000}?)\s{1,100}Operation:""",
    """Object:[^\{\}]{1,2000}?New DN:\s{1,100}({object_dn}[^\s]{1,2000})""",
    """Object:\s{1,100}Old DN:[^\{\}]{1,2000}?({object_ou}OU[^\s]{1,2000}?)\s{1,100}GUID:""",
    """Directory Service:\s{0,100}Name:\s{0,100}({service_name}[^\s]{1,2000})\s{1,100}Type:\s{0,100}({service_type}[^:]{0,2000}?Services)""",
    """GUID:\s{0,100}\{({guid}[^\}]{1,2000})""",
    """Operation:\s{0,100}Correlation ID:\s{0,100}\{({correlation_id}[^\}]{1,2000})""",	
    ]
  DupFields = [ "host->dest_host" ]
}
```