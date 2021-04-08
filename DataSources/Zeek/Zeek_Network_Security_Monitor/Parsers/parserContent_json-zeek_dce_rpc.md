#### Parser Content
```Java
{
Name = json-zeek_dce_rpc
  Product = Zeek Network Security Monitor
  DataType = "remote-access"
  Conditions = [ """ zeek_dce_rpc """, """id.""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"operation\\?"+:\\?"+({process_name}[^"\\]+)"""
    """"endpoint\\?"+:\\?"+({dest_host}[^"\\]+)""",
  ]
}
json-zeek-activity = {
  Vendor = Zeek
  Product = Zeek Network Security Monitor
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