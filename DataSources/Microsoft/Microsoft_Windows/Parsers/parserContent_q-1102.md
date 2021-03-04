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
}
```