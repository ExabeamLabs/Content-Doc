#### Parser Content
```Java
{
Name = bro-network-connection-1
  Product = Bro
  DataType = "network-connection"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"mbps""", """"age_of_conn""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"orig_size":\s*({bytes_in}\d+)""",
    """"resp_size":\s*({bytes_out}\d+)""",
    """"mbps":\s*({mbps}[\d\.]+)""",
    """"age_of_conn":\s*({age_of_conn}[\d\.]+)""",
  ]
}
```