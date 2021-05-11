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
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)'""",
    """<Security UserID='({user_sid}[^']+)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """<Data Name='ScriptBlockId'>({scriptblock_id}[^<]+)</Data>""",
    """Function\s{1,100}'({function}[^']+)""",
    """<Data Name='MessageTotal'>({message_total}\d{1,100})""",
    """<Data Name='MessageNumber'>({message_number}\d{1,100})""",
    """<Message>({script_message}[^:]+)""",
    """<Data Name='Path'>({path}[^<]+)</Data>""",
    """<Execution ProcessID='({pid}\d{1,100})""",
    """({event_code}4104)""",
    """({event_name}Creating Scriptblock text)""",
    """({process_name}PowerShell)""",
    """"ScriptBlockText":"({scriptblock_text}[^"]+?)\s{0,20}""""
  ]
  DupFields = [ "host->dest_host" ]
}
```