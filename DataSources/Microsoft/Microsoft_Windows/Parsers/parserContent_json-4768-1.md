#### Parser Content
```Java
{
Name = json-4768-1
  DataType = "windows-4768"
  Conditions = [ """"event-id":4768""", """"message":"A Kerberos authentication ticket (TGT) was requested""", """"user":""" ]
  Fields = ${WinParserTemplates.json-windows-events.Fields}[
    """"ticket-options":"({ticket_options}[^"]+)""",
    """"ticket-encryption-type":"({ticket_encryption_type}[^"]+)""",
  ]
  DupFields = ["host->dest_host"]
}
```