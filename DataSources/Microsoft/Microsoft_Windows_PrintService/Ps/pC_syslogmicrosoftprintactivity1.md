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
    """TimeGenerated=({time}\d{1,100})""",
    """Computer=({host}[\w\-.]{1,2000})""",
    """User=({user}[^\s]{1,2000})""",
    """Domain=({domain}[^\s]{1,2000})""",
    """EventID=({event_code}\d{1,100})""",
    """Opcode=({outcome}.+?)\s{0,100}(\w+=|$)""",
    """Message=({activity_1}.*?\s{0,100}(?i)Document) \d{1,100}
```