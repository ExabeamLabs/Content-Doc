#### Parser Content
```Java
{
Name = s-trendmicro-epp-alert-1
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "C&C callback detected" , "SourceName=Trend Micro OfficeScan Server" ]
  Fields = [
    """exabeam_raw=.*?({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """ComputerName=({host}[^\s\n]{1,2000})""",
    """\sType=({alert_severity}[^\s\n]{1,2000})""",
    """User=(?:SYSTEM|NOT_TRANSLATED|({user}[^\s\n]{1,2000}))""",
    """RecordNumber=({alert_id}\d{1,100})""",
    """C\&C\s{1,100}({alert_name}.+?)\s{1,100}Compromised Host:""",
    """(Endpoint|Computer|Compromised Host):\s{1,100}({src_host}[^\s\n]{1,2000})""",
    """IP Address:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```