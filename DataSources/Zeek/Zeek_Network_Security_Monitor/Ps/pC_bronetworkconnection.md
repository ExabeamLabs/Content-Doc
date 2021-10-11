#### Parser Content
```Java
{
Name = bro-network-connection
  Product = Zeek Network Security Monitor
  DataType = "network-connection"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"conn_state""", """"orig_pkts""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"orig_ip_bytes\\?"{1,20}:({bytes_in}\d{1,100})""",
    """"resp_ip_bytes\\?"{1,20}:({bytes_out}\d{1,100})""",
    """"sensorname\\?"{1,20}:\\?"{1,20}({sensor_name}[^"]{1,2000})""",
    """"orig_pkts":\s{0,100}({orig_pkts}\d{1,100})""",
    """"resp_pkts":\s{0,100}({resp_pkts}\d{1,100})""",
    """"orig_cc":"({country}[^"]{1,2000})""",
    """"service":"({activity}[^"]{1,2000})""",
  ]
}
json-bro-activity = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"ts\\?"{1,20}:[\[\\]{0,2000}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"]{1,2000})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p\\?"{1,20}:({dest_port}\d{1,100})""",
    """"proto\\?"{1,20}:\\?"{1,20}({protocol}[^"]{1,2000})""",
  ]
}
```