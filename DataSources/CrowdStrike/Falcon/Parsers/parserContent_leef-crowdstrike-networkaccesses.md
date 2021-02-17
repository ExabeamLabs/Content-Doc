#### Parser Content
```Java
{
Name = leef-crowdstrike-networkaccesses
  Conditions = [ """0|CrowdStrike|FalconHost|""", """cat=NetworkAccesses""" ]
  Fields = ${CrowdStrikeParserTemplates.leef-crowdstrike-alert-t.Fields} [
    """CrowdStrike\|([^|]+\|){2}({alert_name}[^|]+)""",
    """\Wdst=({dest_ip}[a-fA-F:\d.]+)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)"""
  ]
}
```