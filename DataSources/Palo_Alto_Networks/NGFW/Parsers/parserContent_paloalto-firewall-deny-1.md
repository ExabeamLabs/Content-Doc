#### Parser Content
```Java
{
Name = paloalto-firewall-deny-1
    Conditions = [""",TRAFFIC,deny,"""]
    Fields = ${PaloAltoParserTemplates.paloalto-firewall.Fields}[
     """TRAFFIC,([^,]*,){42}({outcome}.*?)\s*(,|$)"""
     """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
     """\s({host}[\w.-]+)[\s-]+(\[.*?\]\s+)?\d+,([^,]*,){2}TRAFFIC,""", 
    ]
}
```