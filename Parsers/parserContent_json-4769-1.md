#### Parser Content
```Java
{
Name = json-4769-1
  DataType = "windows-4769"
  Conditions = [ """"event-id":4769""", """"message":"A Kerberos service ticket was requested""" ]
  Fields = ${WinParserTemplates.json-windows-events.Fields}[
    """"ticket-options":"({ticket_options}[^"]+)""",
    """"ticket-encryption-type":"({ticket_encryption_type}[^"]+)""",
    """"service-name":"({src_host}[^\$"]+)""",
    """"ip-address":"(::f+:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```