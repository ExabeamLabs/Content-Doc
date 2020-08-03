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
    """\sUser=({user}.+?)\s+\w+=""",
    """\sDomain=({domain}.+?)\s+\w+=""",
    """\sEventIDCode=({event_code}\d+)""",
    """Message=({activity_1}.*?\s*(?i)Document) \d+,""",
    """owned by [^\s]+\s*.*?( on [^\s]+)?({activity_2}.+?) on ({printer_name}.+?)(\.\s+|\s+through)""",
    """Message=[^,]+,\s+({object}.+?) owned by""",
    """owned by ({user}.+?) (to|on|was) """,
    """owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]+)|({src_host}.+?)) was """,
    """through port (\w+_)?(?:({dest_ip}[A-Fa-f:\d.]+)[_\w]*|\\*({dest_host}.+?))\.\s+""",
    """Size in bytes:\s+({bytes}\d+)""",
    """Pages printed:\s+({num_pages}\d+)""",
  ]
}
```