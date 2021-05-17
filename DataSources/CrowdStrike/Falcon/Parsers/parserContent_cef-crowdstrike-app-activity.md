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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wduser=({user}[^=@]{1,2000}?)(@({domain}[^@]{1,2000}?))?\s{0,100}(\w+=|$)""",
    """CrowdStrike\|([^|]{1,2000}\|){3}({activity}[^|]{1,2000})""",
    """({app}FalconHost)""",
  ]
  DupFields = ["domain->email_domain"]
}
```