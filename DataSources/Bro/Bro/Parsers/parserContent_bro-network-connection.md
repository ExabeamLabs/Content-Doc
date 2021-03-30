#### Parser Content
```Java
{
Name = bro-network-connection
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
json-bro-activity = {
  Vendor = Bro
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts\\?"+:[\[\\]*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"+:\\?"+({conn_id}[^"]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}\d+)""",
    """"proto\\?"+:\\?"+({protocol}[^"]+)""",
  ]

```