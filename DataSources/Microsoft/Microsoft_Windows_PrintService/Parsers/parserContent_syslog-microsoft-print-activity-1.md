#### Parser Content
```Java
{
Name = syslog-microsoft-print-activity-1
  Vendor = Microsoft
  Product = Microsoft Windows PrintService
  Lms = Direct 
  DataType = "print-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """Source=Microsoft-Windows-PrintService""", """EventID=307""", """ owned by """, """ was printed on """]
  Fields = [
    """TimeGenerated=({time}\d+)""",
    """Computer=({host}[\w\-.]+)""",
    """User=({user}[^\s]+)""",
    """Domain=({domain}[^\s]+)""",
    """EventID=({event_code}\d+)""",
    """Opcode=({outcome}.+?)\s*(\w+=|$)""",
    """Message=({activity_1}.*?\s*(?i)Document) \d+,""",
    """Message=.+?owned by [^\s]+\s*.*?( on [^\s]+)?({activity_2}.+?) on ({printer_name}.+?)(\.\s+|\s+through)""",
    """Message=[^,]+,\s+({object}.+?) owned by""",
    """Message=.+?owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]+)|({src_host}.+?)) was """,
    """Message=.+?through port (\w+_)?(?:({dest_ip}[A-Fa-f:\d.]+)|\\*({dest_host}.+?))\.\s+""",
    """Message=.+?Size in bytes:\s*({bytes}\d+)""",
    """Message=.+?Pages printed:\s*({num_pages}\d+)""",
  ]
}
```