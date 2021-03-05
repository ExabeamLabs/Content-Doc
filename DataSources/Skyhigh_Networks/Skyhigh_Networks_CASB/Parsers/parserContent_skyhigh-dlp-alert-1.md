#### Parser Content
```Java
{
Name = skyhigh-dlp-alert-1
  Vendor = Skyhigh Networks
  Product = Skyhigh Networks CASB
  Lms = Splunk
  DataType = "dlp-alert"
  Conditions = [ """,riskLevel=""", """,policy_id=""", """,hierarchy=""", """,userDisplayName=""", """,response=""",  ]
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """,created_on_date=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """\d\d:\d\d:\d\d\s+({host}[\w\-.]+)\s+(\w+=|$)""",
    """,policy_name=({alert_name}[^,]+)""",
    """,type=({alert_type}[^,]+)""",
    """,riskLevel=({alert_severity}[^,]+)""",
    """,hierarchy=({directory}[^,]+)""",
    """,hierarchy=({target}[^,]+)""",
    """,name=({file_name}[^,]+)""",
    """,serviceName=({additional_info}[^,]+)""",
    """,response=({outcome}[^,]+)"""
    """,userDisplayName=({user}[^\s@,]+)""",
    """,size=({bytes}\d+)"""
  ]
}
```