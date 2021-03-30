#### Parser Content
```Java
{
Name = q-1102
  Lms = QRadar
  TimeFormat = "epoch_sec"
  Conditions = [ """EventIDCode=1102""", "The audit log was cleared" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """\sComputer=({host}[\w.\-]+)""",
    """\sTimeGenerated=({time}\d+)\s+"""
  ]
  DupFields = [ "host->dest_host" ]
}
raw-1102 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  DataType = "windows-audit"
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """({event_code}1102)""",
    """({event_name}The audit log was cleared)""",
    """\s+Account Name:\s+({user}.+?)\s+Domain""",
    """\s+Domain Name:\s+({domain}[^\s]+)""",
    """\s+Logon ID:\s+({logon_id}[^\s]+)""",
  ]

```