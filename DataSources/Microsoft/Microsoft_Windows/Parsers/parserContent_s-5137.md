#### Parser Content
```Java
{
Name = s-5137
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-ds-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "EventCode=5137", "A directory service object was created" ]
  Fields = [
    """({event_name}A directory service object was created)""",
    """({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """ComputerName=({host}[\w.\-]{1,2000})""",
    """EventCode=({event_code}\w+)""",
    """Subject:.+?Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Object:.+?Class:\s{1,100}({object_class}.+?)\s{1,100}Operation:""",
    """Object:\s{1,100}DN:\s{1,100}({object_dn}.+?)\s{1,100}GUID:""",
    """Object:\s{1,100}DN:.+?({object_ou}OU.+?)\s{1,100}GUID:""",
    """Directory Service:\s{0,100}Name(:|=)\s{0,100}({service_name}[^\s]{1,2000})\s{0,100}.*?Type(:|=)\s{0,100}({service_type}.*?Services)""",
    """GUID(:|=)\s{0,100}\{({guid}[^\}]{1,2000})""",
    """Operation:\s{0,100}Correlation ID(:|=)\s{0,100}\{({correlation_id}[^\}]{1,2000})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```