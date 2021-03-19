#### Parser Content
```Java
{
Name = paloalto-firewall-allow-2
    TimeFormat = "yyyy/MM/dd HH:mm:ss"
    Conditions = [""",TRAFFIC,""", """,allow,"""]
    Fields = ${PaloAltoParserTemplates.paloalto-firewall.Fields}[
    ]
    DupFields = [ "action->outcome" ]
}
```