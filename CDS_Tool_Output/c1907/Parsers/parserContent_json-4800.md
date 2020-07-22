#### Parser Content
```Java
{
Name = json-4800
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4800"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"EventID":4800""", """The workstation was locked""" ]
  Fields = [
    """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Hostname":"({host}[^"]+)""",
    """({event_name}The workstation was locked)""",
    """({event_code}4800)""",
    """Account Name:\s*((\\)[rnt])*({user}.+?)((\\)[rnt])*\s*Account Domain""",
    """Account Domain:\s*((\\)[rnt])*({domain}.+?)((\\)[rnt])*\s*Logon ID""",
    """Logon ID:\s*((\\)[rnt])*({logon_id}.+?)((\\)[rnt])*\s*Session"""
  ]
  DupFields = [ "host->dest_host" ]
}
```