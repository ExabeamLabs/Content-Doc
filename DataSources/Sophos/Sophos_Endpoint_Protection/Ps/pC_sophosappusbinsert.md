#### Parser Content
```Java
{
Name = sophos-app-usb-insert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Splunk
  DataType = "usb-insert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Action=""", """EventType=Device control;""", """ReportingName=""", """ComputerIPAddress=""", """InsertedAt=""", """USB""" ]
  Fields = [
     """EventID=({event_code}[\d]{1,2000});""",
     """EventTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """EventType=({activity}[^;]{1,2000});""",
     """UserName=([^\\]{1,2000}\\+)?({user}[^;]{1,2000});""",
     """Action=({result}[^;]{1,2000});""",
     """({additional_info}SubType=[^;]{1,2000})""",
     """ComputerName=({dest_host}[^;]{1,2000});""",
     """ComputerIPAddress=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """exabeam_host=({host}[\w\-.]{1,2000})""",
     """ReportingName=({device_id}[^;]{1,2000})""",
     """ReportingName=({device_type}.+?)(/|;)""",
     """ComputerDomain=({domain}[^;]{1,2000})""",
  ]
  DupFields = ["result->activity_details"]
}
```