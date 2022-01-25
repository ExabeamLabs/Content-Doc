#### Parser Content
```Java
{
Name = json-zeek_dhcp
  Product = Zeek Network Security Monitor
  DataType = "dhcp"
  Conditions = [ """ zeek_dhcp """, """msg_type""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"mac"{1,20}:"{1,20}({src_mac}[^"]{1,2000})""",
    """"ts"{1,20}:({time}\d{1,100})""",
    """"uids"{1,20}:\["{1,20}({uids}[^"]{1,2000})""",
    """"msg_types"{1,20}:\["{1,20}({dhcp_type}[^"]{1,2000})""",
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