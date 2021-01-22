#### Parser Content
```Java
{
Name = cef-crowdstrike-app-activity
  Vendor = CrowdStrike
  Product = Falcon
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|CrowdStrike|FalconHost|""", """cat=UserActivityAuditEvent""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wrt=({time}\d+)""",
    """\Wduser=({user}[^=@]+?)(@({domain}[^@]+?))?\s*(\w+=|$)""",
    """CrowdStrike\|([^|]+\|){3}({activity}[^|]+)""",
    """({app}FalconHost)""",
  ]
}
```