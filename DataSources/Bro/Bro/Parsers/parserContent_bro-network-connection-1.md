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