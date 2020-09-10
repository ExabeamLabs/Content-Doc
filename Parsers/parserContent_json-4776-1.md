#### Parser Content
```Java
{
Name = json-4776-1
  DataType = "windows-4776"
  Conditions = [ """"event-id":4776""", """"message":"The computer attempted to validate the credentials for an account""", """"user":""" ]
  Fields = ${WinParserTemplates.json-windows-events.Fields}[
    """"workstation-name":"({dest_host}[^"]+)""",
    """"status-description":"({result_code}[^"\.]+)"""
  ]
}
```