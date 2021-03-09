#### Parser Content
```Java
{
Name = xml-powershell-4104
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<EventID>4104<""", """Microsoft-Windows-PowerShell""", """ScriptBlockText""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z)'""",
    """<Security UserID='({user_sid}[^']+)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<Data Name='ScriptBlockId'>(|({scriptblock_id}[^<]+))</Data>""",
    """<Data Name='ScriptBlockText'>\s*(|({scriptblock_text}[^<]+?))\s*</Data>""",
    """-Function\s+'({function}[^']+)""",
    """<Data Name='MessageTotal'>(|({message_total}\d+))</Data>""",
    """<Data Name='MessageNumber'>(|({message_number}\d+))</Data>""",
    """<Message>({script_message}[^:]+)""",
    """<Data Name='Path'>(|({path}[^<]+))</Data>""",
    """\sProcessID='({pid}\d+)""",
    """({event_code}4104)""",
    """({event_name}Creating Scriptblock text)""",
    """({process_name}PowerShell)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```