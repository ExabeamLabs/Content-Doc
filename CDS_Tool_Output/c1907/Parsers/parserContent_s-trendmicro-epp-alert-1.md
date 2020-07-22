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
    """exabeam_raw=.*?({time}\d+\/\d+\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """ComputerName=({host}[^\s\n]+)""",
    """\sType=({alert_severity}[^\s\n]+)""",
    """User=(?:SYSTEM|NOT_TRANSLATED|({user}[^\s\n]+))""",
    """RecordNumber=({alert_id}\d+)""",
    """C\&C\s+({alert_name}.+?)\s+Compromised Host:""",
    """(Endpoint|Computer|Compromised Host):\s+({src_host}[^\s\n]+)""",
    """IP Address:\s*({src_ip}[A-Fa-f:\d.]+)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```