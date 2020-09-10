#### Parser Content
```Java
{
Name = paloalto-firewall-allow-2
    Conditions = [""",TRAFFIC,""", """,allow,"""]
    Fields = ${PaloAltoParserTemplates.paloalto-firewall.Fields}[
     """TRAFFIC,([^,]*,){48}({host}.*?)\s*,""", 
    ]
}
```