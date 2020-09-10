#### Parser Content
```Java
{
Name = s-4800
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-4800"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ " EventCode=4800", "The workstation was locked." ]
  Fields = [
    """({event_name}The workstation was locked)""",
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))\s+LogName=""",
    """({event_code}4800)""",
    """ComputerName=({host}[^\s]+)""",
    """Account Name:\s+({user}.+?)\s+Account Domain:""",
    """Account Domain:\s+({domain}.+?)\s+Logon ID:""",
    """Logon ID:\s+({logon_id}[^\s]+)\s+Session""",
  ]
  DupFields = [ "host->dest_host" ]
}
```