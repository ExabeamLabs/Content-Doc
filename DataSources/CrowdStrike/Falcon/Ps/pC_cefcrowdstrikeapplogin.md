#### Parser Content
```Java
{
Name = cef-crowdstrike-app-login
  Vendor = CrowdStrike
  Product = Falcon
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|CrowdStrike|FalconHost|""", """cat=AuthActivityAuditEvent""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wduser=({user}[^=@]{1,2000}?)(@({domain}[^@]{1,2000}?))?\s{0,100}(\w+=|$)""",
    """\Woutcome=({outcome}.+?)\s{0,100}(\w+=|$)""",
    """({app}FalconHost)""",
  ]
  DupFields = ["domain->email_domain"]
}
```