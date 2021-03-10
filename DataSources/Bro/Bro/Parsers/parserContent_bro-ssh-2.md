#### Parser Content
```Java
{
Name = bro-ssh-2
  DataType = "ssh-login"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"server":"SSH""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"direction":"({direction}[^"]+)""",
    """"client":"({client}[^"]+)""",
    """"server":"({server}[^"]+)""",
    """"auth_success":({outcome}[^,]+)""",
    """"auth_attempts":({auth_attempts}\d+)""",
  ]
}
```