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
```