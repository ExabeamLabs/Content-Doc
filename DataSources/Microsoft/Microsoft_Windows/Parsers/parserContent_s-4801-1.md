#### Parser Content
```Java
{
Name = s-4801-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-4801"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "EventID=4801", "The workstation was unlocked." ]
  Fields = [
    """({event_name}The workstation was unlocked)""",
    """DetectTime=({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """({event_code}4801)""",
    """ComputerName=({host}[^\s]+)""",
    """Account Name=\s{0,100}({user}.+?)\sSubject""",
    """Account Domain=\s{0,100}({domain}.+?)\s{1,100}Subject""",
    """Logon ID=\s{0,100}({logon_id}[^\s]+)""",
    """Security ID=({user_sid}[^\s]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```