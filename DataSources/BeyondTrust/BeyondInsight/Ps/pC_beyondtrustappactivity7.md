#### Parser Content
```Java
{
Name = beyondtrust-app-activity-7
  Vendor = BeyondTrust
  Product = BeyondInsight
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """act=Add""", """|BeyondTrust|BeyondInsight|""", """fileType=""", """|AppAudit|Add|""" ]
  Fields = [
    """start=({time}\w{3,4}\s\d{1,2}\s\d{4}\s\d{1,2}:\d{1,2}:\d{1,2})""",
    """\w+\s\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\-.]{1,2000})""",
    """src=({src_ip}[A-fa-f\d:.]{1,2000})""",
    """suser=({user}[^\s]{1,2000})""",
    """act=({activity}[^\s]{1,2000})""",
    """dst=({dest_ip}[A-fa-f\d:.]{1,2000})""",
    """BeyondTrustBeyondInsightEventSeverity=({severity}[^\s]{1,2000})""",
    """({app}BeyondInsight)""",
    """fileType=({additional_info}[^=]{1,2000}?)\s\w+=""",
  ]


}
```