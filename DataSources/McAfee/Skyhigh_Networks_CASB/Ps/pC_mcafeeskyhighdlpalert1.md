#### Parser Content
```Java
{
Name = mcafee-skyhigh-dlp-alert-1
  Vendor = McAfee
  Product = Skyhigh Networks CASB
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Conditions = [  """|Alert.Data|""", """activityName =""", """actorIdType=""", """serviceNames=""", """|McAfee|MVISION Cloud|""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s({host}[\w\.\-]{1,2000})""",
    """\|start=({time}\w{3} \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,3} \w{1,3})""",
    """response=\[({outcome}[^\]\s]{1,2000})""",
    """riskSeverity=({alert_severity}[^\s]{1,2000})""",
    """\ssuser=(({user_email}[^@\s=]{1,2000}@[^\s=\.]{1,2000}\.[^\s=]{1,2000})|({user}[^\s=]{1,2000}?))\s{1,100}\w+=""",
    """({alert_type}Alert\.Data)""",
    """\|McAfee\|MVISION Cloud\|[^\|]{1,2000}\|({alert_name}[^\|]{1,2000})\|""",
    """userAction=({action}[^=]{1,2000}?)\s\w+=""",
    """incidentId=({alert_id}[^=]{1,2000}?)\s\w{1,100}=""",
    """serviceNames=\[?(|({additional_info}[^=\]]{1,2000}?))\]?\s{1,100}\w+=""",   
    """\sdhost=({dest_host}[\w\.\-]{1,2000})""",
    """activityName =\[({alert_activity}[^\]]{1,2000}?)\]"""
  ]


}
```