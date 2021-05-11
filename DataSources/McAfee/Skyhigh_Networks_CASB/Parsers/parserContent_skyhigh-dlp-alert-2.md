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
    """\d\d:\d\d:\d\d ({host}[^\s]+) activityName=""",
    """,riskSeverity=({alert_severity}[^,]+)""",
    """,activityName=({alert_name}[^,]+)""",
    """,userAction=({alert_name}[^,]+)""",
    """,destinationHost=({dest_host}[^,]+)""",
    """,userDisplayName=({user}[^,\s]+)""",
    """,incidentId=({alert_id}[^,]+)""",
    """,response=({outcome}[^,]+)""",
    """,riskScore=({risk_score}[^,]+)""",
    """,serviceNames=\[({service_name}[^,\]]+)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```