#### Parser Content
```Java
{
Name = leef-crowdstrike-app-login
  Vendor = CrowdStrike
  Product = Falcon
  Lms = QRadar
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """LEEF:""", """|CrowdStrike|FalconHost|""", """cat=AuthActivityAuditEvent""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\WdevTime=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\WusrName=({user}[^=@]{1,2000}?)(@({domain}[^@]{1,2000}?))?(\s{0,100}\||\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wsuccess=({outcome}.+?)\s{0,100}(\||\w+=|$)""",
    """({app}FalconHost)""",
  ]
  DupFields = ["domain->email_domain"]
}
```