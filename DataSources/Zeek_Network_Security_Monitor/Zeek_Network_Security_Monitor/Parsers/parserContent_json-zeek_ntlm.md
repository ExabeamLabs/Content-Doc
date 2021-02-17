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
```