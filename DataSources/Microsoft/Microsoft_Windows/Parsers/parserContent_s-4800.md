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
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))\s{1,100}LogName=""",
    """({event_code}4800)""",
    """ComputerName=({host}[^\s]{1,2000})""",
    """Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:""",
    """Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:""",
    """Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})\s{1,100}Session""",
  ]
  DupFields = [ "host->dest_host" ]
}
```