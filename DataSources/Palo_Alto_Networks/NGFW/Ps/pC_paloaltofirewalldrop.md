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
     """\s({host}[^\s]{1,2000})\s{1,100}(\[.*?\]\s{1,100})?\d{1,100},([^,]{0,2000},){2}TRAFFIC,""",
     """exabeam_host=({host}[^\s]{1,2000})""",
     """TRAFFIC,("[^"]{0,2000}",|[^,]{0,2000},){48}({host}[\w\-\.]{1,2000})""",
     """:\d\d:\d\d(([+-]\d\d:\d\d)|(\.\d{1,100}Z))?\s{1,100}({host}[\w.-]{1,2000})\s""",
     """({log_type}TRAFFIC)""",
     """TRAFFIC,({subtype}[^,]{1,2000}),""",
     """TRAFFIC,([^,]{0,2000},){2}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
     """TRAFFIC,([^,]{0,2000},){2}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})"""
     """TRAFFIC,([^,]{0,2000},){3}(0.0.0.0|({src_ip}(?!::)[a-fA-F\d.:]{1,2000}))""",
     """TRAFFIC,([^,]{0,2000},){4}(0.0.0.0|({dest_ip}(?!::)[a-fA-F\d.:]{1,2000}))""",
     """TRAFFIC,([^,]{0,2000},){5}(0.0.0.0|({src_translated_ip}(?!::)[a-fA-F\d.:]{1,2000}))""",
     """TRAFFIC,([^,]{0,2000},){6}(0.0.0.0|({dest_translated_ip}(?!::)[a-fA-F\d.:]{1,2000}))""",
     """TRAFFIC,([^,]{0,2000},){7}({rule}[^,]{1,2000}?)\s{0,100},""",
     """TRAFFIC,([^,]{0,2000},){8}\s{0,100}(({user_email}[^@]{1,2000}@[^\.]{1,2000}\.[^,]{1,2000})|(?:({src_domain}[^\s,\\]{1,2000})\\)?({src_user}[^\s,]{1,2000})),""",
     """TRAFFIC,([^,]{0,2000},){9}\s{0,100}(?:({dest_domain}[^\s,\\]{1,2000})\\)?({dest_user}[^\s,]{1,2000}),""",
     """TRAFFIC,([^,]{0,2000},){10}(not-applicable|({network_app}[^,]{1,2000}?))\s{0,100},""",
     """TRAFFIC,([^,]{0,2000},){12}({src_network_zone}[^,]{1,2000}?)\s{0,100},""",
     """TRAFFIC,([^,]{0,2000},){13}({dest_network_zone}[^,]{1,2000}?)\s{0,100},""",
     """TRAFFIC,([^,]{0,2000},){20}(0|({src_port}\d{1,100})),""",
     """TRAFFIC,([^,]{0,2000},){21}(0|({dest_port}\d{1,100})),""",
     """TRAFFIC,([^,]{0,2000},){22}(0|({src_translated_port}\d{1,100})),""",
     """TRAFFIC,([^,]{0,2000},){23}(0|({dest_translated_port}\d{1,100})),""",
     """TRAFFIC,([^,]{0,2000},){25}({protocol}[^,]{1,2000}?)\s{0,100},""",
     """TRAFFIC,([^,]{0,2000},){26}({action}[^,]{1,2000}?)\s{0,100},""",
     """TRAFFIC,([^,]{0,2000},){27}({bytes}\d{1,100})""",
     """TRAFFIC,([^,]{0,2000},){28}({bytes_out}\d{1,100})""",
     """TRAFFIC,([^,]{0,2000},){29}({bytes_in}\d{1,100})""",
     """TRAFFIC,([^,]{0,2000},){33}(any|unknown|({category}[^,]{1,2000}?)\s{0,100},)""",
     """TRAFFIC,([^,]{0,2000},){37}({src_country}[^\.:]{0,2000}?)\s{0,100},""",
     """TRAFFIC,([^,]{0,2000},){38}({dest_country}[^\.:]{0,2000}?)\s{0,100},""",
   ]

```