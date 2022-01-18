#### Parser Content
```Java
{
Name = cef-powershell-4104
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF: """, """|Microsoft|PowerShell|""", """|Microsoft-Windows-PowerShell:4104|""", """|Creating Scriptblock text""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"UserId"":""({user_sid}.+?)"""",
    """"Computer"":""({host}.+?)"""",
    """"ScriptBlockId"":""({scriptblock_id}.+?)"""",
    """"ScriptBlockText"":""({scriptblock_text}.+?)"""",
    """-Function\s{1,100}'({function}[^']{1,2000})""",
    """"MessageTotal"":""(|({message_total}.+?))"""",
    """"MessageNumber"":""(|({message_number}.+?))"""",
    """message=({script_message}[^:]{1,2000})""",
    """"Path"":""(|({path}.+?))"""",
    """"ProcessID"":""({pid}\d{1,100})"""",
    """duser=({user}[^\s]{1,2000})""", 
  ]


}
```