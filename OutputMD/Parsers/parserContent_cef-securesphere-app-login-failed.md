#### Parser Content
```Java
{
Name = cef-securesphere-app-login-failed
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Imperva Inc.|SecureSphere""", """cat=SystemEvent""", """|Login failed|""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """\srt=({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
    """\ssuser=({user}.+?)\s*(\w+=|$)""",
    """\|Login failed for user ({user}[^\s\(\)]+)""",
    """\|Login failed for user.*?\(IP: ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\) Reason: ({failure_reason}[^\|]+)\|"""
  ]
}
```