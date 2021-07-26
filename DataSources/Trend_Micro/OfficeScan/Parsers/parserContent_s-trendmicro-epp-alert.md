#### Parser Content
```Java
{
Name = s-trendmicro-epp-alert
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "Virus/Malware:" , "SourceName=Trend Micro OfficeScan Server" ]
  Fields = [
    """exabeam_raw=.*?({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """ComputerName=({host}[^\s\n]{1,2000})""",
    """\sType=({alert_severity}[^\s\n]{1,2000})""",
    """User=(?:SYSTEM|NOT_TRANSLATED|({user}[^\s\n]{1,2000}))""",
    """RecordNumber=({alert_id}\d{1,100})""",
    """Virus/Malware:\s({alert_name}.+?)\s{1,100}(Endpoint|Computer):""",
    """(Endpoint|Computer):\s{1,100}({src_host}[^\s\n]{1,2000})""",
    """File:\s{1,100}({malware_url}.+?)\s{1,100}Date"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```