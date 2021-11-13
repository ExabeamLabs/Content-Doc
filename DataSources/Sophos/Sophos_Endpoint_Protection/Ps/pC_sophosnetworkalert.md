#### Parser Content
```Java
{
Name = sophos-network-alert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Action=""", """EventType=Device control;""", """ReportingName =""", """ComputerIPAddress="""  ]
  Fields = [
    """EventID=({alert_id}[\d]{1,2000});""",
    """EventTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """EventType=({alert_name}[^;]{1,2000});""",
    """Action=({outcome}[^;]{1,2000});""",
    """UserName =([^\\]{1,2000}\\+)?({user}[^;]{1,2000});""",
    """ReportingName =({additional_info}.+?);""",
    """({additional_info}SubType=[^;]{1,2000})""",
    """ComputerName =({src_host}[^;]{1,2000});""",
    """ComputerIPAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """ComputerDomain=({domain}[^;]{1,2000})""",
    """exabeam_host=({host}[\w\-.]{1,2000})""",
   ]
  DupFields = [ "outcome->alert_severity" ] 


}
```