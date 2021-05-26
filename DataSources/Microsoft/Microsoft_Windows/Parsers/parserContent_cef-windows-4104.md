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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\s{0,100}({host}[^\s]{1,2000})\s""",
    """eventid="{1,20}({event_code}\d{1,100})""",
    """providername="{1,20}({provider_name}[^"]{1,2000})""",
    """userid="(?:[^\\]{1,2000}\\+)?(SYSTEM|NETWORK SERVICE|({user}[^"]{1,2000}))""",
    """\stask="{1,20}({activity}[^"]{1,2000})""",
    """\Weventrecordid="{1,20}({record_id}\d{1,100})"""",
    """({event_name}Creating Scriptblock text)""",
    """ScriptBlock ID:\s{1,100}({scriptblock_id}[^\s]{1,2000})""",
    """({process_name}PowerShell)""",
    """Creating Scriptblock text\s{0,100}\([^\)]{1,2000}\):\s{0,100}({scriptblock_text}.+?)\s{0,100}ScriptBlock ID:""",
  ]
  DupFields = ["event_id->event_code"]
}
```