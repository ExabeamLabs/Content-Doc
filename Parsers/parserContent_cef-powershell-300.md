#### Parser Content
```Java
{
Name = cef-powershell-300
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF: """, """|Microsoft|PowerShell|""", """PowerShell:300|""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"UserId"":""({user_sid}.+?)"""",
    """"Computer"":""({host}.+?)"""",
    """"ScriptBlockId"":""({scriptblock_id}.+?)"""",
    """"ScriptBlockText"":""({scriptblock_text}.+?)"""",
    """-Function\s+'({function}[^']+)""",
    """"MessageTotal"":""(|({message_total}.+?))"""",
    """"MessageNumber"":""(|({message_number}.+?))"""",
    """message=({script_message}[^:]+)""",
    """"Path"":""(|({path}.+?))"""",
    """"ProcessID"":""({pid}\d+)"""",
  ]
}
```