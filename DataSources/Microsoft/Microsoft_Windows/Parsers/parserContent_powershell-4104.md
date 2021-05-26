#### Parser Content
```Java
{
Name = powershell-4104
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """Microsoft-Windows-PowerShell (4104)""", """Microsoft-Windows-PowerShell/Operational""" ]
  Fields = [
    """({host}\S+)\s{1,100}\S+ - - - \S+\s{1,100}\S+\s{1,100}({time}\w{3}\s\d\d\s\d\d:\d\d:\d\d\s\d{4}):[^\(]{1,2000}\(({event_code}\d{1,100})\) - \\*"{1,20}({script_message}[^:]{1,2000}):""",
    """ScriptBlock ID:\s{1,100}({scriptblock_id}[^\s]{1,2000})""",
    """Creating Scriptblock text \([^\)]{1,2000}\):({scriptblock_text}.+)\s{1,100}ScriptBlock ID:""",
    """\(({event_code}4104)\)""",
    """({process_name}PowerShell)"""
  ]
}
```