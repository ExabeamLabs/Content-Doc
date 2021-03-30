#### Parser Content
```Java
{
Name = json-zeek_weird
  Product = Zeek Network Security Monitor
  DataType = "network-alert"
  Conditions = [ """ zeek_weird """, """"id.orig_h""", """"id.resp_h""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"name\\?"+:\\?"+({alert_name}[^"\\]+)""",
    """"peer\\?"+:\\?"+({src_host}[^"\\]+)"""
  ]
}
json-zeek-activity = {
  Vendor = Zeek
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