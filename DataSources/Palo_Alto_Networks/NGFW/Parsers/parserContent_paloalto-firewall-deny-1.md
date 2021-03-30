#### Parser Content
```Java
{
Name = paloalto-firewall-deny-1
    Conditions = [""",TRAFFIC,deny,"""]
    Fields = ${PaloAltoParserTemplates.paloalto-firewall.Fields}[
     """TRAFFIC,([^,]*,){42}({outcome}.*?)\s*(,|$)"""
     """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
     """\s({host}[^\s]+)[\s-]+(\[.*?\]\s+)?\d+,([^,]*,){2}TRAFFIC,""",
    ]
}
paloalto-firewall = {
   Vendor = Palo Alto Networks
   Product = NGFW
   Lms = Direct
   DataType = "network-connection"
   IsHVF = true
   TimeFormat = "yyyy/MM/dd HH:mm:ss"
   Fields = [
     """\s({host}[^\s]+)\s+(\[.*?\]\s+)?\d+,([^,]*,){2}TRAFFIC,""",
     """({log_type}TRAFFIC)""",
     """TRAFFIC,({subtype}[^,]+),""",
     """TRAFFIC,([^,]*,){2}({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
     """TRAFFIC,([^,]*,){3}(0.0.0.0|({src_ip}(?!::)[a-fA-F\d.:]+))""",
     """TRAFFIC,([^,]*,){4}(0.0.0.0|({dest_ip}(?!::)[a-fA-F\d.:]+))""",
     """TRAFFIC,([^,]*,){5}(0.0.0.0|({src_translated_ip}(?!::)[a-fA-F\d.:]+))""",
     """TRAFFIC,([^,]*,){6}(0.0.0.0|({dest_translated_ip}(?!::)[a-fA-F\d.:]+))""",
     """TRAFFIC,([^,]*,){7}({rule}.*?)\s*,""",
     """TRAFFIC,([^,]*,){8}\s*(?:({src_domain}[^\s,\\]+)\\)?({src_user}[^\s,]+),""",
     """TRAFFIC,([^,]*,){9}\s*(?:({dest_domain}[^\s,\\]+)\\)?({dest_user}[^\s,]+),""",
     """TRAFFIC,([^,]*,){10}(not-applicable|({network_app}.*?))\s*,""",
     """TRAFFIC,([^,]*,){12}({src_network_zone}.*?)\s*,""",
     """TRAFFIC,([^,]*,){13}({dest_network_zone}.*?)\s*,""",
     """TRAFFIC,([^,]*,){20}(0|({src_port}\d+)),""",
     """TRAFFIC,([^,]*,){21}(0|({dest_port}\d+)),""",
     """TRAFFIC,([^,]*,){22}(0|({src_translated_port}\d+)),""",
     """TRAFFIC,([^,]*,){23}(0|({dest_translated_port}\d+)),""",
     """TRAFFIC,([^,]*,){25}({protocol}.*?)\s*,""",
     """TRAFFIC,([^,]*,){26}({action}.*?)\s*,""",
     """TRAFFIC,([^,]*,){27}({bytes}\d+)""",
     """TRAFFIC,([^,]*,){28}({bytes_out}\d+)""",
     """TRAFFIC,([^,]*,){29}({bytes_in}\d+)""",
     """TRAFFIC,([^,]*,){33}({category}.*?)\s*,""",
     """TRAFFIC,([^,]*,){37}({src_country}[^\.:]*?)\s*,""",
     """TRAFFIC,([^,]*,){38}({dest_country}[^\.:]*?)\s*,""",
   ]

```