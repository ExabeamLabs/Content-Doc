#### Parser Content
```Java
{
Name = json-bro-ssl-failed
  DataType = "authentication-failed"
  Conditions = [ """note":"SSL::Invalid_Server_Cert"""", """"id.orig_h":""", """"id.resp_h":"""]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"msg":"({reason}[^"]+)""",
    """({auth_method}SSL)"""
  ]
}
```