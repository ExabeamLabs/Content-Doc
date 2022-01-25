#### Parser Content
```Java
{
Name = json-zeek-network-connection-2
  Product = Zeek Network Security Monitor
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"_path":"dpd""",""""id.orig_h":"""",""""uid":"""",""""id.resp_p":""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"ts":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
  ]


json-zeek-activity = {
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Splunk
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
    """"_system_name":"({host}[\w\-.]{1,2000})"""",
    """"ts"{1,20}:({time}\d{1,100})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"\\]{1,2000})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]{1,2000})""",
  
}
```