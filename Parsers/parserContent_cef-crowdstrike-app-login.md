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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wrt=({time}\d+)""",
    """\Wduser=({user}[^=@]+?)(@({domain}[^@]+?))?\s*(\w+=|$)""",
    """\Woutcome=({outcome}.+?)\s*(\w+=|$)""",
    """({app}FalconHost)""",
  ]
}
```