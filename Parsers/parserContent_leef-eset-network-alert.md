#### Parser Content
```Java
{
Name = leef-eset-network-alert
  DataType = "network-alert"
  Conditions = [ """LEEF:""", """|ESET|RemoteAdministrator|""", """cat=ESET Firewall Event""" ]
  Fields = ${ESETParserTemplates.eset-activity.Fields}[
    """eventDesc=({alert_name}[^=]+?)\s*(\w+=|$)""",
    """scannerID=({additional_info}[^=]+?)\s*(\w+=|$)""",
    """\Wsev=({alert_severity}\d+)"""
  ]
  DupFields = ["event_name->alert_type"]
}
```