#### Parser Content
```Java
{
Name = skyhigh-dlp-alert
  Vendor = McAfee
  Product = Skyhigh Networks CASB
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "anomaly.timeupdated=",",activityName=", ",MimeType="]
  Fields = [
            """\d{1,100}:\d{1,100}:\d{1,100}\s({host}[^\s]{1,2000})\s\w+=""",
            """,timestamp=({time}\d\d\d\d\-\d\d\-\d\dT\d{1,100}:\d{1,100}:\d{1,100})""",
            """\sriskLevel=({alert_severity}[^,]{1,2000})""",
            """,userAction=({alert_name}[^,]{1,2000})""",
            """,destinationHost=({dest_host}[^,]{1,2000})""",
            """,userDisplayName=({user}[^,]{1,2000})""",
            """,ByteCount=({bytes}[^,]{1,2000})""",
            """,MimeType=({additional_info}[^,]{1,2000})""",
            """,response=({outcome}[^,]{1,2000})""",
           ]
    DupFields = [ "alert_name->alert_type" ]
}
```