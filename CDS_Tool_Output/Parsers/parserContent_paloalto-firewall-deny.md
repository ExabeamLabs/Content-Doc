#### Parser Content
```Java
{
Name = paloalto-firewall-deny
    Conditions = [""",TRAFFIC,""", """,deny,""", """PANORAMA"""]
    Fields = ${PaloAltoParserTemplates.paloalto-firewall.Fields}[
     """TRAFFIC,([^,]*,){42}({outcome}.*?)\s*(,|$)"""
    ]
}
```