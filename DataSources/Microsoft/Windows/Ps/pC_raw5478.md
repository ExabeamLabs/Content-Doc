#### Parser Content
```Java
{
Name = raw-5478
  Vendor = Microsoft
  Product = Windows
  Lms = Syslog
  DataType = "service-created"
  TimeFormat = "dd/MM/yyyy HH:mm:ss aa"
  Conditions = [ """EventCode=5478""", """SourceName =Microsoft Windows security auditing""", """Message=The IPsec Policy Agent service was started""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d ((?i)AM|PM))""",
    """ComputerName =({host}[\w.-]{1,2000})""",
    """EventCode=({event_code}5478)""",
    """Message=({event_name}The IPsec Policy Agent service was started)""",
    """Keywords=({outcome}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """RecordNumber=({record_id}[^\s]{1,2000})""",
    """TaskCategory=({service_type}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """({service_name}IPsec Policy Agent)"""
  ]
  DupFields = ["host->dest_host"]


}
```