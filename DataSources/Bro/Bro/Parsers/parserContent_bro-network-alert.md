#### Parser Content
```Java
{
Name = bro-network-alert
  DataType = "network-alert"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"_path":"weird_red"""", """"peer":"""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"name":"({alert_name}[^"]+)""",
    """"peer":"({src_host}[^"]+)"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```