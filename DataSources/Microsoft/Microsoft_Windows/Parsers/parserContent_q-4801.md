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
  Fields = [ """EventID=({event_code}\d+)""",
    """({event_name}The workstation was unlocked)""",
    """TimeGenerated=({time}\d+)""",
    """Computer=({host}[^\s]+)""",
    """Account Name:\s+({user}.+?)\s+Account Domain""",
    """Account Domain:\s+({domain}.+?)\s+Logon ID""",
    """Logon ID:\s+({logon_id}[^\s]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```