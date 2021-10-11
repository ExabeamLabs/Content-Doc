#### Parser Content
```Java
{
Name = q-microsoft-print-activity
  Vendor = Microsoft
  Product = Windows PrintService
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
    """Message=({activity_1}.*?\s{0,100}(?i)Document) \d{1,100},""",
    """owned by [^\s]{1,2000}\s{0,100}.*?( on [^\s]{1,2000})?({activity_2}.+?) on ({printer_name}.+?)(\.\s{1,100}|\s{1,100}through)""",
    """Message=[^,]{1,2000},\s{1,100}({object}.+?) owned by""",
    """owned by ({user}.+?) (to|on|was) """,
    """owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}.+?)) was """,
    """through port (\w+_)?(?:({dest_ip}[A-Fa-f:\d.]{1,2000})[_\w]{0,2000}|\\*({dest_host}.+?))\.\s{1,100}""",
    """Size in bytes:\s{1,100}({bytes}\d{1,100})""",
    """Pages printed:\s{1,100}({num_pages}\d{1,100})""",
  ]
}
```