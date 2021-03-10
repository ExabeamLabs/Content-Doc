#### Parser Content
```Java
{
Name = xml-powershell-4104
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """4104""", """Microsoft-Windows-PowerShell""", """ScriptBlockText""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Security UserID='({user_sid}[^']+)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Data Name='ScriptBlockId'>(|({scriptblock_id}.+?))</Data>""",
    """<Data Name='ScriptBlockText'>\s*(|({scriptblock_text}.+?))\s*</Data>""",
    """-Function\s+'({function}[^']+)""",
    """<Data Name='MessageTotal'>(|({message_total}.+?))</Data>""",
    """<Data Name='MessageNumber'>(|({message_number}.+?))</Data>""",
    """<Message>({script_message}[^:]+)""",
    """<Data Name='Path'>(|({path}.+?))</Data>""",
    """\sProcessID='({pid}\d+)""",
  ]
}
```