#### Parser Content
```Java
{
Name = skyhigh-dlp-alert-1
  Vendor = McAfee
  Product = Skyhigh Networks CASB
  Lms = Splunk
  DataType = "dlp-alert"
  Conditions = [ """,riskLevel=""", """,policy_id=""", """,hierarchy=""", """,userDisplayName=""", """,response=""",  ]
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """,created_on_date=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}(\w+=|$)""",
    """,policy_name=({alert_name}[^,]{1,2000})""",
    """,type=({alert_type}[^,]{1,2000})""",
    """,riskLevel=({alert_severity}[^,]{1,2000})""",
    """,hierarchy=({directory}[^,]{1,2000})""",
    """,hierarchy=({target}[^,]{1,2000})""",
    """,name=({file_name}[^,]{1,2000})""",
    """,serviceName=({additional_info}[^,]{1,2000})""",
    """,response=({outcome}[^,]{1,2000})"""
    """,userDisplayName=({user}[^\s@,]{1,2000})""",
    """,size=({bytes}\d{1,100})"""
  ]
}
```