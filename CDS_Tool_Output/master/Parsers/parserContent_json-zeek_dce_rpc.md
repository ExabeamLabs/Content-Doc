#### Parser Content
```Java
{
Name = json-zeek_dce_rpc
  DataType = "remote-access"
  Conditions = [ """ zeek_dce_rpc """, """id.""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"operation\\?"+:\\?"+({process_name}[^"\\]+)"""
    """"endpoint\\?"+:\\?"+({dest_host}[^"\\]+)""",
  ]
}
```