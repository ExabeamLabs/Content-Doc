#### Parser Content
```Java
{
Name = json-zeek_dns
  DataType = "dns-query"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """ zeek_dns """ ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"query"+:"+({query}[^"]+)""",
    """"qtype_name"+:"+({query_type}[^"]+)""",
    """"proto\\?"+:\\?"+({protocol}[^"]+)""",
  ]
}
json-zeek-activity = {
  Vendor = Bro
  Product = Bro
  Lms = Splunk
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts"+:({time}\d+)""",
    """"uid\\?"+:\\?"+({conn_id}[^"\\]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}[a-fA-F\d.:]+)""",
  ]

```