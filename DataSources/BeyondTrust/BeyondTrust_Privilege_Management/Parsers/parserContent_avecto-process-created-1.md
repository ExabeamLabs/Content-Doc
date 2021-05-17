#### Parser Content
```Java
{
Name = avecto-process-created-1
  Vendor = BeyondTrust
  Product = BeyondTrust Privilege Management
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """, ProcessStartTime="""", """, ProcessStartTimeMs="""" ]
  Fields = [
    """\WProcessStartTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\WHostName="({host}[^"]{1,2000})""",
    """\WEventNumber="({event_code}\d{1,100})""",
    """\WUserName="(({domain}[^\\"]{1,2000})\\)?({user}[^\\"]{1,2000})""",
    """\WEventDescription="({additional_info}[^"]{1,2000})""",
    """\WFileName="({process}({directory}(?:(\w+:)?[^:"]{1,2000})?[\\\/])?({process_name}.+?))"""",
    """\WCommandLine="({command_line}.+?)",""",
    """\WProductName="(<None>|({product_name}[^"]{1,2000}))""",
    """\WPublisher="(<None>|({publisher}[^"]{1,2000}))""",
    """\WReason="(<None>|({reason}[^"]{1,2000}))""",
    """\WProcessGUID="({process_guid}[^"]{1,2000})""",
    """\WParentProcessUniqueID="({parent_process_guid}[^"]{1,2000})""",
    """\WPID="({pid}[^"]{1,2000})""",
    """\WUserSID="({user_sid}[^"]{1,2000})""",
    """\WApplicationHash="({md5}[^"]{1,2000})""",
    """\WActivityType="({activity_type}[^"]{1,2000})""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```