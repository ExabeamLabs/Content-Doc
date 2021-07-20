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
    """"Hostname":"({host}[^"]{1,2000})""",
    """({event_name}The workstation was locked)""",
    """({event_code}4800)""",
    """Account Name:\s{0,100}((\\)[rnt])*({user}.+?)((\\)[rnt])*\s{0,100}Account Domain""",
    """Account Domain:\s{0,100}((\\)[rnt])*({domain}.+?)((\\)[rnt])*\s{0,100}Logon ID""",
    """Logon ID:\s{0,100}((\\)[rnt])*({logon_id}.+?)((\\)[rnt])*\s{0,100}Session"""
  ]
  DupFields = [ "host->dest_host" ]
}
```