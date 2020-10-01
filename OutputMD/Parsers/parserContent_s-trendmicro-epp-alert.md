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
    """exabeam_raw=.*?({time}\d+\/\d+\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """ComputerName=({host}[^\s\n]+)""",
    """\sType=({alert_severity}[^\s\n]+)""",
    """User=(?:SYSTEM|NOT_TRANSLATED|({user}[^\s\n]+))""",
    """RecordNumber=({alert_id}\d+)""",
    """Virus/Malware:\s({alert_name}.+?)\s+(Endpoint|Computer):""",
    """(Endpoint|Computer):\s+({src_host}[^\s\n]+)""",
    """File:\s+({malware_url}.+?)\s+Date"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```