#### Parser Content
```Java
{
Name = xml-5138
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>5138<""", """A directory service object was undeleted.""" ]
  Fields = [
    """({event_name}A directory service object was undeleted)""",
    """({event_code}5138)""",
    """<Computer>({host}[^<]{1,2000})<""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^<]{1,2000}))<""",
    """Security ID:\s{1,100}({user_sid}[^\s]{1,2000}?)\s{1,100}Account Name:\s{1,100}({user}[^\s]{1,2000}?)\s{1,100}Account Domain:\s{1,100}((?i)(NA)|({domain}[^\s]{1,2000}?))\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Class:\s{1,100}({object_class}[^:]{1,2000}?)\s{1,100}Operation:""",
    """Object:[^\{\}]{1,2000}?New DN:\s{1,100}({object_dn}[^\s]{1,2000})""",
    """Object:\s{1,100}Old DN:[^\{\}]{1,2000}?({object_ou}OU[^\s]{1,2000}?)\s{1,100}GUID:""",
    """Directory Service:\s{0,100}Name:\s{0,100}({service_name}[^\s]{1,2000})\s{1,100}Type:\s{0,100}({service_type}[^:]{0,2000}?Services)""",
    """<Data Name='ObjectGUID'>\{({guid}[^<\}]{1,2000})\}<""",
    """<Data Name='OpCorrelationID'>\{({correlation_id}[^\}<]{1,2000})\}<""",
  ]
}
```