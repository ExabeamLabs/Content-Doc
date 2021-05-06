#### Parser Content
```Java
{
Name = sophos-app-activity-failed-1
  DataType = "app-activity"
  Conditions = [ """Action=Blocked;""", """EventType=Adware or PUA;""", """ReportingName=""", """ComputerIPAddress="""  ] 
  Fields=${SophosParserTemplates.sophos-endpoint-events.Fields}[
    """SubType=({failure_reason}[^;]+)"""
  ]
}
sophos-endpoint-events = {
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
     """EventID=({event_code}[\d]+);""",
     """EventTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """EventType=({activity}[^;]+);""",
     """Name=({app}[^;]+);""",
     """UserName=([^\\]+\\+)?({user}[^;]+);""",
     """Action=({result}[^;]+);""",
     """({additional_info}SubType=[^;]+)""",
     """ComputerName=({src_host}[^;]+);""",
     """ComputerIPAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """exabeam_host=({host}[\w\-.]+)""",
     """ComputerDomain=({domain}[^;]+)""",
   ]

```