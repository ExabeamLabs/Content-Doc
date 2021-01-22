#### Parser Content
```Java
{
Name = s-kaspersky-es-alert
  Vendor = Kaspersky Lab
  Product = Kaspersky Endpoint Security for Business
  Lms = Splunk
  DataType = "alert"
  TimeFormat =  "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """Kaspersky Event Log""","""Result\Name:""" ]
  Fields = [
	   """ComputerName=({host}[\w.\-]+)""",
           """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
	   """Message=({src_host}.+?)\s*\[""",
           """User:\s+({domain}[^\\]*)\\({user}.+?)\s*\(""",
	   """Object:\s+({malware_url}.+?)\s*(Result|Object)\\""",
	   """Result\\Name:\s*({alert_type}.+?)\s*Result\\""",
           """Result\\Type:\s*({alert_type}.+?)\s*Result\\""",
           """Result\\Name:\s*({alert_name}.+?)\s*Result\\""",
	   """Result\\Threat level:\s*({alert_severity}.+?)\s*Result\\"""
           ]
}
```