#### Parser Content
```Java
{
Name = leef-crowdstrike-networkaccesses
  Conditions = [ """0|CrowdStrike|FalconHost|""", """cat=NetworkAccesses""" ]
  Fields = ${CrowdStrikeParserTemplates.leef-crowdstrike-alert-t.Fields} [
    """CrowdStrike\|([^|]+\|){2}({alert_type}[^|]+)""",
    """\Wdst=({alert_name}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\Wdst=({malware_url}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)"""
  ]
}
```