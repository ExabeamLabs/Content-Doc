#### Parser Content
```Java
{
Name = raw-4622
  Vendor = Microsoft
  Product = Windows
  Lms = Syslog
  DataType = "service-created"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventCode=4622""", """SourceName =Microsoft Windows security auditing""", """A security package has been loaded by the Local Security Authority""", """ComputerName =""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d \w\w)""",  
    """({event_code}4622)""",
    """ComputerName =({host}[\w\-\.]{1,2000})""",
    """({event_name}A security package has been loaded by the Local Security Authority)""",
    """Keywords=({outcome}[^=]{1,200}?)\s{0,100}\w+=""",
    """Security Package Name:\s{0,100}({service_name}[^$]{1,200}?)\s{0,100}("|$)""",
    """RecordNumber=({record_id}\w{1,2000})""",
  ]
  DupFields = ["host->dest_host"]


}
```