#### Parser Content
```Java
{
Name = json-zeek_dhcp
  Product = Zeek Network Security Monitor
  DataType = "dhcp"
  Conditions = [ """ zeek_dhcp """, """msg_type""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"mac"+:"+({src_mac}[^"]+)""",
    """"ts"+:({time}\d+)""",
    """"uids"+:\["+({uids}[^"]+)""",
    """"msg_types"+:\["+({dhcp_type}[^"]+)""",
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