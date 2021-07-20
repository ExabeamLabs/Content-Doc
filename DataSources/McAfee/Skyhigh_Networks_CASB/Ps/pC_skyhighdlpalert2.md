#### Parser Content
```Java
{
Name = skyhigh-dlp-alert-2
  Vendor = McAfee
  Product = Skyhigh Networks CASB
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Conditions = [ """ activityName=""", """MimeType,""", """,userAction=""" ]
  Fields = [
    """,updatedOn="({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\d\d:\d\d:\d\d ({host}[^\s]{1,2000}) activityName=""",
    """,riskSeverity=({alert_severity}[^,]{1,2000})""",
    """,activityName=({alert_name}[^,]{1,2000})""",
    """,userAction=({alert_name}[^,]{1,2000})""",
    """,destinationHost=({dest_host}[^,]{1,2000})""",
    """,userDisplayName=({user}[^,\s]{1,2000})""",
    """,incidentId=({alert_id}[^,]{1,2000})""",
    """,response=({outcome}[^,]{1,2000})""",
    """,riskScore=({risk_score}[^,]{1,2000})""",
    """,serviceNames=\[({service_name}[^,\]]{1,2000})""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```