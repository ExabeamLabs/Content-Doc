#### Parser Content
```Java
{
Name = eset-domain-user-failed-login
    Vendor = ESET
    Product = ESET Endpoint Security
    Lms = Splunk
    DataType = "authentication-failed"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ """LEEF:""", """|ESET|RemoteAdministrator|""", """cat=ESET RA Audit Event""", """|Failed domain user login|""" ]
    Fields = [
      """\Wcat=({category}[^=]+?)\s{0,100}(\w+=|$)""",
      """\Wsev=({alert_severity}\d{1,100})""",
      """\WdevTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
      """\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
      """\Waction=({activity}[^\s]+)\s""",
      """\Wresult=({outcome}[^=]+?)\s{0,100}(\w+=|$)""",
      """\WdeviceName=({host}[^\s]+)\s""",
      """\Wtarget=({object}[^\s]+)\s{0,100}""",
      """\Wdetail=({additional_info}[^.]+).""",
      """\Wuser '\w+\\({user}[^\s]+)'.""",
      """(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\|({event_name}[^|]+)\|""",
      """({service}RemoteAdministrator)""",
      """\d{1,100}Z\s{0,100}({host}\w+)\s""",
    ]
  }
```