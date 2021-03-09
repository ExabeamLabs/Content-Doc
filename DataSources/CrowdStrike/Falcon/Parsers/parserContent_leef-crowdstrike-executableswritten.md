#### Parser Content
```Java
{
Name = leef-crowdstrike-executableswritten
  Conditions = [ """0|CrowdStrike|FalconHost|""", """cat=ExecutablesWritten""" ]
  Fields = ${CrowdStrikeParserTemplates.leef-crowdstrike-alert-t.Fields} [
    """CrowdStrike\|([^|]+\|){2}({alert_name}[^|]+)""",
    """\WexeWrittenFileName=({file_name}[^|"]+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\WexeWrittenFilePath=({malware_url}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\WexeWrittenFilePath=({process}({directory}[^=]*\\+)\s*({process_name}.+?)?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)"""
  ]
}
```