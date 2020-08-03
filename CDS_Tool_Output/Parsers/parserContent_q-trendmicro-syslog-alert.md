#### Parser Content
```Java
{
Name = q-trendmicro-syslog-alert
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ "OfficeScan", "Virus found action result" ]
  Fields = [
     """({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
     """result\s+\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} \w{2}\s+.+[AP]M\s+[^\s]+\s+({src_ip}[^\s]+).+?\s({alert_name}OfficeScan)\s+[^\s]+\s+({alert_type}\w+)\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+({src_host}[^\s+]+)"""
  ]
  DupFields = [ "src_host->host" ]
}
```