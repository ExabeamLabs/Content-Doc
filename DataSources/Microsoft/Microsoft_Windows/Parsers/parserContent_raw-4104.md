#### Parser Content
```Java
{
Name = raw-4104
  Lms = Splunk
  Vendor = Microsoft
  Product = Microsoft Windows
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  DataType = "process-created"
  Conditions = [ """4104""", """Microsoft-Windows-PowerShell""", """Creating Scriptblock text"""  ]
  Fields = [
    """({time}\w{3}\s\d\d\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s({host}[^\s]+)\sMSWinEventLog""",
    """({event_code}4104)""",
    """Microsoft-Windows-PowerShell\s+(SYSTEM|NETWORK SERVICE|({user}.+?))\s+User""",
    """ComputerName:\s*({host}[\w.-]+)"""
    """TimeStamp:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """User:\s*({user}.+?)\s*\w+:""",
    """({event_name}Creating Scriptblock text)""",
    """ScriptBlock ID:\s+({scriptblock_id}[^\s]+)""",
    """({process_name}PowerShell)""",
    """Process ID:\s*({pid}\d+)""",
    """Creating Scriptblock text\s*\([^\)]+\):\s*({scriptblock_text}.+?)\s*ScriptBlock ID:""",
  ]
}
```