#### Parser Content
```Java
{
Name = q-microsoft-print-activity
  Vendor = Microsoft
  Product = Microsoft Windows PrintService
  Lms = QRadar
  DataType = "print-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """Source=Print""", """EventIDCode=1""" ]
  Fields = [
    """\sTimeGenerated=({time}\d{10})""",
    """\sComputer=({host}\S+)""",
    """\sUser=({user}.+?)\s{1,100}\w+=""",
    """\sDomain=({domain}.+?)\s{1,100}\w+=""",
    """\sEventIDCode=({event_code}\d{1,100})""",
    """Message=({activity_1}.*?\s{0,100}(?i)Document) \d{1,100

}
```