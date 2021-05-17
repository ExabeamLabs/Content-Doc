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
     """({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
     """result\s{1,100}\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} \w{2}\s{1,100}.+[AP]M\s{1,100}[^\s]{1,2000}\s{1,100}({src_ip}[^\s]{1,2000}).+?\s({alert_name}OfficeScan)\s{1,100}[^\s]{1,2000}\s{1,100}({alert_type}\w+)\s{1,100}[^\s]{1,2000}\s{1,100}[^\s]{1,2000}\s{1,100}[^\s]{1,2000}\s{1,100}[^\s]{1,2000}\s{1,100}[^\s]{1,2000}\s{1,100}({src_host}[^\s]{1,2000})"""
  ]
  DupFields = [ "src_host->host" ]
}
```