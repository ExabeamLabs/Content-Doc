#### Parser Content
```Java
{
Name = json-zeek-kerberos
  Product = Zeek Network Security Monitor
  DataType = "remote-access"
  Conditions = [ """ zeek_kerberos """, """"id.orig_h""", """"id.resp_h""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"client\\?"+:\\?"+({user}[^"\\]+)""",
    """"request_type\\?"+:\\?"+({request_type}[^"\\]+)""",
    """"client\\?"+:\\?"+({user}[^"\/\\]+)(\/({domain}[^"\\]+))?""",
    """"service\\?"+:\\?"+({service_name}[^"\/\\@]+)""",
    """"success\\?"+:({outcome}\w+)""",
    """"cipher\\?"+:\\?"+({ticket_encryption_type}[^"\\]+)"""
  ]
}
```