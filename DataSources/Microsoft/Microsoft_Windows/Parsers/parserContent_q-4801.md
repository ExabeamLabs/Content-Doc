#### Parser Content
```Java
{
Name = q-4801
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-4801"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=4801", "The workstation was unlocked" ]
  Fields = [ """EventID=({event_code}\d{1,100})""",
    """({event_name}The workstation was unlocked)""",
    """TimeGenerated=({time}\d{1,100})""",
    """Computer=({host}[^\s]+)""",
    """Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain""",
    """Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID""",
    """Logon ID:\s{1,100}({logon_id}[^\s]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```