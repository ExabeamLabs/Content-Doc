#### Parser Content
```Java
{
Name = paloalto-firewall-allow
   Conditions = [""",TRAFFIC,""", """,allow,""", """APC-PANORAMA-LOGS"""]
    Fields = ${PaloAltoParserTemplates.paloalto-firewall.Fields}[
     """TRAFFIC,([^,]*,){48}({host}.*?)\s*,""",
    ]
}
```