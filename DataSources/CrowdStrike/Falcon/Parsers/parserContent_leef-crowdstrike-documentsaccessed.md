#### Parser Content
```Java
{
Name = leef-crowdstrike-documentsaccessed
  Conditions = [ """0|CrowdStrike|FalconHost|""", """cat=DocumentsAccessed""" ]
  Fields = ${CrowdStrikeParserTemplates.leef-crowdstrike-alert-t.Fields} [
    """CrowdStrike\|([^|]+\|){2}({alert_name}[^|]+)""",
    """\WdocAccessedFileName=({file_name}[^|"]+?)\s*(\||\w+=|$|"+\s*$)""",
    """\WdocAccessedFilePath=({file_parent}.+?)\s*(\||\w+=|$|"+\s*$)""",
    """\Wdescription=({additional_info}.+?)\s*(\||\w+=|$|"+\s*$)"""
  ]
   DupFields = ["file_parent->malware_url", "category->alert_type"]
}
```