#### Parser Content
```Java
{
Name = json-bro-ssl-failed-2
  DataType = "authentication-failed"
  Conditions = [ """server_name":""", """"resumed":""", """"id.resp_h":""", """"established":false"""]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"server_name":"({server}[^"]+)""",
    """"established":({outcome}[^,]+)""",
  ]
}
```