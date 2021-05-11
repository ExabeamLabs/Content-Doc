#### Parser Content
```Java
{
Name = q-1102
  Lms = QRadar
  TimeFormat = "epoch_sec"
  Conditions = [ """EventIDCode=1102""", "The audit log was cleared" ]
  Fields = ${WinParserTemplates.raw-1102.Fields} [
    """\sComputer=({host}[\w.\-]+)""",
    """\sTimeGenerated=({time}\d{1,100})\s{1,100}"""
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
    """\s{1,100}Account Name:\s{1,100}({user}.+?)\s{1,100}Domain""",
    """\s{1,100}Domain Name:\s{1,100}({domain}[^\s]+)""",
    """\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]+)""",
  ]

```