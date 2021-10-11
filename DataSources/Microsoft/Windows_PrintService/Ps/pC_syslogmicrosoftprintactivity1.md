#### Parser Content
```Java
{
Name = syslog-microsoft-print-activity-1
  Vendor = Microsoft
  Product = Windows PrintService
  Lms = Direct 
  DataType = "print-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """Source=Microsoft-Windows-PrintService""", """EventID=307""", """ owned by """, """ was printed on """]
  Fields = [
    """TimeGenerated=({time}\d{1,100})""",
    """Computer=({host}[\w\-.]{1,2000})""",
    """User=({user}[^\s]{1,2000})""",
    """Domain=({domain}[^\s]{1,2000})""",
    """EventID=({event_code}\d{1,100})""",
    """Opcode=({outcome}.+?)\s{0,100}(\w+=|$)""",
    """Message=({activity_1}.*?\s{0,100}(?i)Document) \d{1,100},""",
    """Message=.+?owned by [^\s]{1,2000}\s{0,100}.*?( on [^\s]{1,2000})?({activity_2}.+?) on ({printer_name}.+?)(\.\s{1,100}|\s{1,100}through)""",
    """Message=[^,]{1,2000},\s{1,100}({object}.+?) owned by""",
    """Message=.+?owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}.+?)) was """,
    """Message=.+?through port (\w+_)?(?:({dest_ip}[A-Fa-f:\d.]{1,2000})|\\*({dest_host}.+?))\.\s{1,100}""",
    """Message=.+?Size in bytes:\s{0,100}({bytes}\d{1,100})""",
    """Message=.+?Pages printed:\s{0,100}({num_pages}\d{1,100})""",
  ]
}
```