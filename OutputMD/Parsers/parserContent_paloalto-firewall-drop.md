#### Parser Content
```Java
{
Name = paloalto-firewall-drop
    Conditions = [""",TRAFFIC,drop,"""]
    Fields = ${PaloAltoParserTemplates.paloalto-firewall.Fields}[
     """TRAFFIC,([^,]*,){42}({outcome}.*?)\s*(,|$)""", 
    ]
}
```