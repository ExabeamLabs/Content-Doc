#### Parser Content
```Java
{
Name = json-zeek_ssl
  Product = Zeek Network Security Monitor
  DataType = "authentication-successful"
  Conditions = [ """ zeek_ssl """, """"id.orig_h""", """"id.resp_h""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"version\\?"+:\\?"+({service}[^"\\]+)""",
    """"cipher\\?"+:\\?"+({auth_method}[^"\\]+)"""
    """"established\\?"+:({outcome}\w+)""",
    """"validation_status"+:"+({failure_reason}[^"]+)""",
  ]
}
```