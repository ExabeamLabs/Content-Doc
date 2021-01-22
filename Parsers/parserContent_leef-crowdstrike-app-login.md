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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\WdevTime=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\WusrName=({user}[^=@]+?)(@({domain}[^@]+?))?(\s*\||\s+\w+=|\s*$|\s*")""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wsuccess=({outcome}.+?)\s*(\||\w+=|$)""",
    """({app}FalconHost)""",
  ]
}
```