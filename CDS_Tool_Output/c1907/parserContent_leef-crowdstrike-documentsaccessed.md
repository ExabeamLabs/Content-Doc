#### Parser Content
```Java
{
Name = leef-crowdstrike-documentsaccessed
  Conditions = [ """0|CrowdStrike|FalconHost|""", """cat=DocumentsAccessed""" ]
  Fields = ${CrowdStrikeParserTemplates.leef-crowdstrike-alert-t.Fields} [
    """CrowdStrike\|([^|]+\|){2}({alert_type}[^|]+)""",
    """\WdocAccessedFileName=({alert_name}.+?)\s*(\||\w+=|$|"+\s*$)""",
    """\WdocAccessedFileName=({file_name}.+?)\s*(\||\w+=|$|"+\s*$)""",
    """\WdocAccessedFilePath=({malware_url}.+?)\s*(\||\w+=|$|"+\s*$)""",
    """\WdocAccessedFilePath=({file_parent}.+?)\s*(\||\w+=|$|"+\s*$)""",
    """\Wdescription=({additional_info}.+?)\s*(\||\w+=|$|"+\s*$)"""
  ]
}
```