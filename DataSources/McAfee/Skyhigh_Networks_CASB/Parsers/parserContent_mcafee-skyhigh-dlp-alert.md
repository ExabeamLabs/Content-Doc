#### Parser Content
```Java
{
Name = mcafee-skyhigh-dlp-alert
  Vendor = McAfee
  Product = Skyhigh Networks CASB
  Lms = QRadar
  DataType = "dlp-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Conditions = [  """cat=Alert.Policy.Dlp""", """activityName=""", """actorIdType=""", """serviceNames=""", """|McAfee|MVISION Cloud|""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s({host}[^\s]+)""",
    """devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d+ \w+)""",
    """src=(0\.0\.0\.0|({src_ip}[\da-fA-F:\.]+))""",
    """policyName=({alert_name}[^=]+?)\s+\w+=""",
    """policyId=({alert_id}[^\s]+)""",
    """contentItemName=({file_name}[^=]+)\s+\w+=""",
    """response=\[({outcome}[^\]\s]+)""",
    """FileSize=({bytes}\d+)""",
    """riskSeverity=({alert_severity}[^\s]+)""",
    """({additional_info}totalMatchCount=[^\s]+)""",
    """contentItemId=({target}[^=]+?)\s+\w+=""",
    """instanceName=({src_host}[^=]+?)\s+\w+=""",
    """usrName=(({user_email}[^@]+@[^@\s]+)|({user}[^\s]+))\s+sev""",
    """activityName=\[({alert_type}[^\]]+?)\]"""
  ]
}
```