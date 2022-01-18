#### Parser Content
```Java
{
Name = json-zeek_dns
  Product = Zeek Network Security Monitor
  DataType = "dns-query"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """ zeek_dns """ ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"query"{1,20}:"{1,20}({query}[^"]{1,2000})""",
    """"qtype_name"{1,20}:"{1,20}({query_type}[^"]{1,2000})""",
    """"proto\\?"{1,20}:\\?"{1,20}({protocol}[^"]{1,2000})""",
  ]

json-zeek-activity = {
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Splunk
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"ts"{1,20}:({time}\d{1,100})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"\\]{1,2000})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]{1,2000})""",
  
}
```