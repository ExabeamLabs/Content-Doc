#### Parser Content
```Java
{
Name = s-kaspersky-es-alert
  Vendor = Kaspersky
  Product = Kaspersky Endpoint Security for Business
  Lms = Splunk
  DataType = "alert"
  TimeFormat =  "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """Kaspersky Event Log""","""Result\Name:""" ]
  Fields = [
	   """ComputerName=({host}[\w.\-]{1,2000})""",
           """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
	   """Message=({src_host}.+?)\s{0,100}\[""",
           """User:\s{1,100}({domain}[^\\]{0,2000})\\({user}.+?)\s{0,100}\(""",
	   """Object:\s{1,100}({malware_url}.+?)\s{0,100}(Result|Object)\\""",
	   """Result\\Name:\s{0,100}({alert_type}.+?)\s{0,100}Result\\""",
           """Result\\Type:\s{0,100}({alert_type}.+?)\s{0,100}Result\\""",
           """Result\\Name:\s{0,100}({alert_name}.+?)\s{0,100}Result\\""",
	   """Result\\Threat level:\s{0,100}({alert_severity}.+?)\s{0,100}Result\\"""
           ]
}
```