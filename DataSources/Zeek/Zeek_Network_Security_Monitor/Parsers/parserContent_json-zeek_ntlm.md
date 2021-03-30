#### Parser Content
```Java
{
Name = json-zeek_ntlm
  Product = Zeek Network Security Monitor
  DataType = "ntlm-logon"
  Conditions = [ """ zeek_ntlm """, """"id.orig_h""", """"id.resp_h""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"server_nb_computer_name"+:"+({sub_domain}[^"]+)""",
    """"server_dns_computer_name"+:"+({dns_domain}[^"]+)""",
    """"server_tree_name"+:"+({domain}[^"]+)"""
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