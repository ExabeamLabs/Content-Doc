#### Parser Content
```Java
{
Name = bro-network-connection
  Product = Bro
  DataType = "network-connection"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"conn_state""", """"orig_pkts""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"orig_ip_bytes\\?"+:({bytes_in}\d+)""",
    """"resp_ip_bytes\\?"+:({bytes_out}\d+)""",
    """"sensorname\\?"+:\\?"+({sensor_name}[^"]+)""",
    """"orig_pkts":\s*({orig_pkts}\d+)""",
    """"resp_pkts":\s*({resp_pkts}\d+)""",
    """"orig_cc":"({country}[^"]+)""",
    """"service":"({activity}[^"]+)""",
  ]
}
```