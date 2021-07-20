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
    """\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})""",
    """devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100} \w+)""",
    """src=(0\.0\.0\.0|({src_ip}[\da-fA-F:\.]{1,2000}))""",
    """policyName=({alert_name}[^=]{1,2000}?)\s{1,100}\w+=""",
    """policyId=({alert_id}[^\s]{1,2000})""",
    """contentItemName=({file_name}[^=]{1,2000})\s{1,100}\w+=""",
    """response=\[({outcome}[^\]\s]{1,2000})""",
    """FileSize=({bytes}\d{1,100})""",
    """riskSeverity=({alert_severity}[^\s]{1,2000})""",
    """({additional_info}totalMatchCount=[^\s]{1,2000})""",
    """contentItemId=({target}[^=]{1,2000}?)\s{1,100}\w+=""",
    """instanceName=({src_host}[^=]{1,2000}?)\s{1,100}\w+=""",
    """usrName=(({user_email}[^@]{1,2000}@[^@\s]{1,2000})|({user}[^\s]{1,2000}))\s{1,100}sev""",
    """activityName=\[({alert_type}[^\]]{1,2000}?)\]"""
  ]
}
```