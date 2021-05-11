#### Parser Content
```Java
{
Name = paloalto-firewall-drop
    TimeFormat = "yyyy/MM/dd HH:mm:ss"
    Conditions = [""",TRAFFIC,drop,"""]
    Fields = ${PaloAltoParserTemplates.paloalto-firewall.Fields}[
    ]
    DupFields = [ "action->outcome" ]
}
paloalto-firewall = {
   Vendor = Palo Alto Networks
   Product = NGFW
   Lms = Direct
   DataType = "network-connection"
   IsHVF = true
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
   Fields = [
     """\s({host}[^\s]+)\s{1,100}(\[.*?\]\s{1,100})?\d{1,100},([^,]*,){2}TRAFFIC,""",
     """exabeam_host=({host}[^\s]+)""",
     """TRAFFIC,("[^"]*",|[^,]*,){48}({host}[\w\-\.]+)""",
     """:\d\d:\d\d(([+-]\d\d:\d\d)|(\.\d{1,100}Z))?\s{1,100}({host}[\w.-]+)\s""",
     """({log_type}TRAFFIC)""",
     """TRAFFIC,({subtype}[^,]+),""",
     """TRAFFIC,([^,]*,){2}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
     """TRAFFIC,([^,]*,){2}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})"""
     """TRAFFIC,([^,]*,){3}(0.0.0.0|({src_ip}(?!::)[a-fA-F\d.:]+))""",
     """TRAFFIC,([^,]*,){4}(0.0.0.0|({dest_ip}(?!::)[a-fA-F\d.:]+))""",
     """TRAFFIC,([^,]*,){5}(0.0.0.0|({src_translated_ip}(?!::)[a-fA-F\d.:]+))""",
     """TRAFFIC,([^,]*,){6}(0.0.0.0|({dest_translated_ip}(?!::)[a-fA-F\d.:]+))""",
     """TRAFFIC,([^,]*,){7}({rule}[^,]+?)\s{0,100},""",
     """TRAFFIC,([^,]*,){8}\s{0,100}(({user_email}[^@]+@[^\.]+\.[^,]+)|(?:({src_domain}[^\s,\\]+)\\)?({src_user}[^\s,]+)),""",
     """TRAFFIC,([^,]*,){9}\s{0,100}(?:({dest_domain}[^\s,\\]+)\\)?({dest_user}[^\s,]+),""",
     """TRAFFIC,([^,]*,){10}(not-applicable|({network_app}[^,]+?))\s{0,100},""",
     """TRAFFIC,([^,]*,){12}({src_network_zone}[^,]+?)\s{0,100},""",
     """TRAFFIC,([^,]*,){13}({dest_network_zone}[^,]+?)\s{0,100},""",
     """TRAFFIC,([^,]*,){20}(0|({src_port}\d{1,100})),""",
     """TRAFFIC,([^,]*,){21}(0|({dest_port}\d{1,100})),""",
     """TRAFFIC,([^,]*,){22}(0|({src_translated_port}\d{1,100})),""",
     """TRAFFIC,([^,]*,){23}(0|({dest_translated_port}\d{1,100})),""",
     """TRAFFIC,([^,]*,){25}({protocol}[^,]+?)\s{0,100},""",
     """TRAFFIC,([^,]*,){26}({action}[^,]+?)\s{0,100},""",
     """TRAFFIC,([^,]*,){27}({bytes}\d{1,100})""",
     """TRAFFIC,([^,]*,){28}({bytes_out}\d{1,100})""",
     """TRAFFIC,([^,]*,){29}({bytes_in}\d{1,100})""",
     """TRAFFIC,([^,]*,){33}(any|unknown|({category}[^,]+?)\s{0,100},)""",
     """TRAFFIC,([^,]*,){37}({src_country}[^\.:]*?)\s{0,100},""",
     """TRAFFIC,([^,]*,){38}({dest_country}[^\.:]*?)\s{0,100},""",
   ]

```