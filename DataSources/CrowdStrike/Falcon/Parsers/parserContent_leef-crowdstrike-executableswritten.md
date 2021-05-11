#### Parser Content
```Java
{
Name = leef-crowdstrike-executableswritten
  Conditions = [ """0|CrowdStrike|FalconHost|""", """cat=ExecutablesWritten""" ]
  Fields = ${CrowdStrikeParserTemplates.leef-crowdstrike-alert-t.Fields} [
    """CrowdStrike\|([^|]+\|){2}({alert_name}[^|]+)""",
    """\WexeWrittenFileName=({file_name}[^|"]+?)(\t|\s{1,100}\w+=|\s{0,100}\||\s{0,100}$|\s{0,100}"{1,20}\s{0,100}$)""",
    """\WexeWrittenFilePath=({malware_url}.+?)(\t|\s{1,100}\w+=|\s{0,100}\||\s{0,100}$|\s{0,100}"{1,20}\s{0,100}$)""",
    """\WexeWrittenFilePath=({process}({directory}[^=]*\\+)\s{0,100}({process_name}.+?)?)(\t|\s{1,100}\w+=|\s{0,100}\||\s{0,100}$|\s{0,100}"{1,20}\s{0,100}$)"""
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
      """\Wduser=(?!N\/A)({user}[^=@]+?)(@({domain}[^@]+?))?(\t|\s{1,100}\w+=|\s{0,100}\||\s{0,100}$|\s{0,100}"{1,20}\s{0,100}$)""",
      """\WusrName=(?!N\/A)({user}[^=@]+?)(@({domain}[^@]+?))?(\t|\s{1,100}\w+=|\s{0,100}\||\s{0,100}$|\s{0,100}"{1,20}\s{0,100}$)""",
      """\Wdomain=(?!N\/A)({domain}[^=]+?)(\t|\s{1,100}\w+=|\s{0,100}\||\s{0,100}$|\s{0,100}"{1,20}\s{0,100}$)""",
      """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\WsrcPort=({src_port}\d{1,100})""",
      """\WdstPort=({dest_port}\d{1,100})""",
      """\Wcat=({category}[^\|]+?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """\Wproto=({protocol}[^\s]+?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """\WfileName=({file_name}.+?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """\Wresource=({src_host}.+?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """\Wsev=({alert_severity}.+?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """CrowdStrike\|([^|]+\|){2}({alert_name}[^|]+)""",
      """\Wurl=({additional_info}[^\|]+?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """\Wmd5=({md5}[^\s]+?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """({app}FalconHost)"""
    ]

```