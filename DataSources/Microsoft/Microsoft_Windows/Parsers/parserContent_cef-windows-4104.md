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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{0,100}({host}[^\s]+)\s""",
    """eventid="{1,20}({event_code}\d{1,100})""",
    """providername="{1,20}({provider_name}[^"]+)""",
    """userid="(?:[^\\]+\\+)?(SYSTEM|NETWORK SERVICE|({user}[^"]+))""",
    """\stask="{1,20}({activity}[^"]+)""",
    """\Weventrecordid="{1,20}({record_id}\d{1,100})"""",
    """({event_name}Creating Scriptblock text)""",
    """ScriptBlock ID:\s{1,100}({scriptblock_id}[^\s]+)""",
    """({process_name}PowerShell)""",
    """Creating Scriptblock text\s{0,100}\([^\)]+\):\s{0,100}({scriptblock_text}.+?)\s{0,100}ScriptBlock ID:""",
  ]
  DupFields = ["event_id->event_code"]
}
```