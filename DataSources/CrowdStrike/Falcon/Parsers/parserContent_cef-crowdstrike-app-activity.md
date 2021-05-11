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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wduser=({user}[^=@]+?)(@({domain}[^@]+?))?\s{0,100}(\w+=|$)""",
    """CrowdStrike\|([^|]+\|){3}({activity}[^|]+)""",
    """({app}FalconHost)""",
  ]
  DupFields = ["domain->email_domain"]
}
```