#### Parser Content
```Java
{
Name = sophos-app-activity-failed
  DataType = "app-activity"
  Conditions = [ """Action=Blocked;""", """EventType=Application control;""", """ReportingName=""", """ComputerIPAddress="""  ] 
}

${SophosParserTemplates.sophos-endpoint-events} {
  Name = sophos-app-activity-failed-1
  DataType = "app-activity"
  Conditions = [ """Action=Blocked;""", """EventType=Adware or PUA;""", """ReportingName=""", """ComputerIPAddress="""  ] 
  Fields=${SophosParserTemplates.sophos-endpoint-events.Fields}[
    """SubType=({failure_reason}[^;]+)"""
  ]
}

{
  Name = sophos-app-usb-insert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Splunk
  DataType = "usb-insert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Action=""", """EventType=Device control;""", """ReportingName=""", """ComputerIPAddress=""", """InsertedAt=""", """USB""" ]
  Fields = [
     """EventID=({event_code}[\d]+);""",
     """EventTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """EventType=({activity}[^;]+);""",
     """UserName=([^\\]+\\+)?({user}[^;]+);""",
     """Action=({result}[^;]+);""",
     """({additional_info}SubType=[^;]+)""",
     """ComputerName=({dest_host}[^;]+);""",
     """ComputerIPAddress=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """exabeam_host=({host}[\w\-.]+)""",
     """ReportingName=({device_id}[^;]+)""",
     """ReportingName=({device_type}.+?)(/|;)""",
     """ComputerDomain=({domain}[^;]+)""",
  ]
  DupFields = ["result->activity_details"]
}
```