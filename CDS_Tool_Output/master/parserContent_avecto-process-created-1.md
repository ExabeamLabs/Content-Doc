#### Parser Content
```Java
{
Name = avecto-process-created-1
  Vendor = Avecto Defendpoint Service
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """, ProcessStartTime="""", """, ProcessStartTimeMs="""" ]
  Fields = [
    """\WProcessStartTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
    """\WHostName="({host}[^"]+)""",
    """\WEventNumber="({event_code}\d+)""",
    """\WUserName="(({domain}[^\\"]+)\\)?({user}[^\\"]+)""",
    """\WEventDescription="({additional_info}[^"]+)""",
    """\WFileName="({process}({directory}(?:(\w+:)?[^:"]+)?[\\\/])?({process_name}.+?))"""",
    """\WCommandLine="({command_line}.+?)",""",
    """\WProductName="(<None>|({product_name}[^"]+))""",
    """\WPublisher="(<None>|({publisher}[^"]+))""",
    """\WReason="(<None>|({reason}[^"]+))""",
    """\WProcessGUID="({process_guid}[^"]+)""",
    """\WParentProcessUniqueID="({parent_process_guid}[^"]+)""",
    """\WPID="({pid}[^"]+)""",
    """\WUserSID="({user_sid}[^"]+)""",
    """\WApplicationHash="({md5}[^"]+)""",
    """\WActivityType="({activity_type}[^"]+)""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```