#### Parser Content
```Java
{
Name = leef-crowdstrike-detectionsummaryevent
  Conditions = [ """0|CrowdStrike|FalconHost|""", """cat=DetectionSummaryEvent""" ]
  Fields = ${CrowdStrikeParserTemplates.leef-crowdstrike-alert-t.Fields} [
    """CrowdStrike\|([^|]+\|){2}({alert_type}[^|]+)""",
    """\WfileName=({alert_name}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\WfilePath=({malware_url}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\WfilePath=({file_parent}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\Wdescription=({additional_info}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\WcommandLine="({command_line}[^"]+)""""
  ]
}
leef-crowdstrike-alert-t = {
    Vendor = CrowdStrike
    Product = Falcon
    Lms = QRadar
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=({host}[\w\-.]+)""",
      """\WdevTime=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\Wduser=(?!N\/A)({user}[^=@]+?)(@({domain}[^@]+?))?(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
      """\WusrName=(?!N\/A)({user}[^=@]+?)(@({domain}[^@]+?))?(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
      """\Wdomain=(?!N\/A)({domain}[^=]+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
      """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\WsrcPort=({src_port}\d+)""",
      """\WdstPort=({dest_port}\d+)""",
      """\Wcat=({additional_info}.+?)\s*(\||\w+=|$|"+\s*$)""",
      """\Wproto=({protocol}[^\s]+?)\s*(\||\w+=|$|"+\s*$)""",
      """\WfileName=({file_name}.+?)\s*(\||\w+=|$|"+\s*$)""",
      """\Wresource=({src_host}.+?)\s*(\||\w+=|$|"+\s*$)""",
      """\Wsev=({alert_severity}.+?)\s*(\||\w+=|$|"+\s*$)""",
      """CrowdStrike\|([^|]+\|){2}({alert_name}[^|]+)""",
      """\Wurl=({alert_id}.+?)\s*(\||\w+=|$|"+\s*$)""",
      """\Wmd5=({md5}[^\s]+?)\s*(\||\w+=|$|"+\s*$)""",
      """({app}FalconHost)"""
    ]

```