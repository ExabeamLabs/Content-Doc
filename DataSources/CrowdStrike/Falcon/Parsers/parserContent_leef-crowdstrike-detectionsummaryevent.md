#### Parser Content
```Java
{
Name = leef-crowdstrike-detectionsummaryevent
  Conditions = [ """0|CrowdStrike|FalconHost|""", """cat=DetectionSummaryEvent""" ]
  Fields = ${CrowdStrikeParserTemplates.leef-crowdstrike-alert-t.Fields} [
    """CrowdStrike\|([^|]+\|){2}({alert_name}[^|]+)""",
    """\WfileName=({file_name}[^|"]+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\WfilePath=({file_parent}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\Wdescription=({additional_info}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\WcommandLine="({command_line}[^"]+)"""",
    """\WfilePath=({process}[^\s]+\\+({process_name}[^\s]+))""",
    """sha256=({sha256}[^|\s]+?)\s*(\||\w+=)"""
  ]
   DupFields = ["file_parent->malware_url", "category->alert_type"]
}
```