#### Parser Content
```Java
{
Name = bro-smb_mapping-2
  Product = Zeek Network Security Monitor
  DataType = "share-access"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"share_type""", """"path""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"path":"({share_path}[^"]+)""",
    """"service":"({service}[^"]+)""",
    """"share_type":"({share_type}[^"]+)""",
  ]
}
```