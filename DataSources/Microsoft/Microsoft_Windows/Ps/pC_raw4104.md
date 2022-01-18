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
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})\sMSWinEventLog""",
    """({event_code}4104)""",
    """Microsoft-Windows-PowerShell\s{1,100}(SYSTEM|NETWORK SERVICE|({user}.+?))\s{1,100}User""",
    """ComputerName:\s{0,100}({host}[\w.-]{1,2000})"""
    """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """User:\s{0,100}({user}.+?)\s{0,100}\w+:""",
    """({event_name}Creating Scriptblock text)""",
    """ScriptBlock ID:\s{1,100}({scriptblock_id}[^\s]{1,2000})""",
    """({process_name}PowerShell)""",
    """Process ID:\s{0,100}({pid}\d{1,100})""",
    """Creating Scriptblock text\s{0,100}\([^\)]{1,2000}\):\s{0,100}({scriptblock_text}.+?)\s{0,100}ScriptBlock ID:""",
  ]


}
```