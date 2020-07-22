#### Parser Content
```Java
{
Name = s-trendmicro-epp-alert-2
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "Spyware/Grayware:" , "SourceName=Trend Micro OfficeScan Server" ]
  Fields = [
    """exabeam_raw=.*?({time}\d+\/\d+\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """ComputerName=({host}[^\s\n]+)""",
    """\sType=({alert_severity}[^\s\n]+)""",
    """User=(?:SYSTEM|NOT_TRANSLATED|({user}[^\s\n]+))""",
    """RecordNumber=({alert_id}\d+)""",
    """Spyware/Grayware:\s({alert_name}.+?)\s+Computer:""",
    """(Endpoint|Computer):\s+({src_host}[^\s\n]+)"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```