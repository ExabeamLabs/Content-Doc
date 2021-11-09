#### Parser Content
```Java
{
Name = sophos-app-activity-failed
  DataType = "app-activity"
  Conditions = [ """Action=Blocked;""", """EventType=Application control;""", """ReportingName=""", """ComputerIPAddress="""  ] 
}
sophos-endpoint-events = {
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
     """EventID=({event_code}[\d]{1,2000});""",
     """EventTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """EventType=({activity}[^;]{1,2000});""",
     """Name=({app}[^;]{1,2000});""",
     """UserName=([^\\]{1,2000}\\+)?({user}[^;]{1,2000});""",
     """Action=({result}[^;]{1,2000});""",
     """({additional_info}SubType=[^;]{1,2000})""",
     """ComputerName=({src_host}[^;]{1,2000});""",
     """ComputerIPAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """exabeam_host=({host}[\w\-.]{1,2000})""",
     """ComputerDomain=({domain}[^;]{1,2000})""",
   ]}
```