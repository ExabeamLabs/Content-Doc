#### Parser Content
```Java
{
Name = eset-domain-user-login
    Vendor = ESET
    Product = ESET Endpoint Security
    Lms = Splunk
    DataType = "authentication-successful"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "LEEF:1.0|ESET|RemoteAdministrator|", """cat=ESET""", """|Domain user login|""" ]
    Fields = [
      """(\s|\|)cat=({category}.+?)\s*(\w+=|$)""",
      """(\s|\|)sev=({alert_severity}\d+)""",
      """(\s|\|)devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
      """(\s|\|)src=({src_ip}(\d{1,3}\.){3}\d{1,3})""",
      """\Waction=({activity}[^\s]+)\s""",
      """\Wresult=({outcome}.+?)\s*$""",
      """\WdeviceName=({host}[^\s]+)\s""",
      """\Wtarget=({object}[^\s]+)\s*""",
      """\Wdetail=({additional_info}[^.]+).""",
      """\Wuser '\w+\\({user}[^\s]+)'.""",
      """(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\|({event_name}[^|]+)\|""",
      """({service}RemoteAdministrator)""", 
      """\d+Z\s*({host}\w+)\s""",
    ]
  }
```