#### Parser Content
```Java
{
Name = json-4624-1
  DataType = "windows-4624"
  Conditions = [ """"event-id":4624""", """"message":"An account was successfully logged on""", """"user":""" ]
  Fields = ${WinParserTemplates.json-windows-events.Fields}[
    """"target-logon-id":"({logon_id}[^"]+)"""
  ]
}
```