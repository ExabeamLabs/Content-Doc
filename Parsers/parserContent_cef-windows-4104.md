#### Parser Content
```Java
{
Name = cef-windows-4104
  Lms = Splunk
  Vendor = Microsoft
  Product = Microsoft Windows
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  DataType = "process-created"
  Conditions = [ """eventid="4104"""", """Microsoft-Windows-PowerShell""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d+Z\s*({host}[^\s]+)\s""",
    """eventid="+({event_code}\d+)""",
    """providername="+({provider_name}[^"]+)""",
    """userid="(?:[^\\]+\\+)?(SYSTEM|NETWORK SERVICE|({user}[^"]+))""",
    """\stask="+({activity}[^"]+)""",
    """\Weventrecordid="+({record_id}\d+)"""",
    """({event_name}Creating Scriptblock text)""",
    """ScriptBlock ID:\s+({scriptblock_id}[^\s]+)""",
    """({process_name}PowerShell)""",
    """Creating Scriptblock text\s*\([^\)]+\):\s*({scriptblock_text}.+?)\s*ScriptBlock ID:""",
  ]
  DupFields = ["event_id->event_code"]
}
```