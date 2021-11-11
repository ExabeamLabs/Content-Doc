#### Parser Content
```Java
{
Name = leef-crowdstrike-networkaccesses
  DataType = "network-connection"
  Conditions = [ """LEEF:""", """|CrowdStrike|FalconHost|""", """cat=NetworkAccesses""" ]
  Fields = ${CrowdStrikeParserTemplates.leef-crowdstrike-alert-t.Fields} [
    """CrowdStrike\|([^|]{1,2000}\|){2}({alert_name}[^|]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F:\d.]{1,2000})(\t|\s{1,100}\w{1,1000}=|\s{0,100}\||\s{0,100}$|\s{0,100}"{1,20}\s{0,100}$)"""
  ]
}
leef-crowdstrike-alert-t = {
    Vendor = CrowdStrike
    Product = Falcon
    Lms = QRadar
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=({host}[\w\-.]{1,2000})""",
      """\WdevTime=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\Wduser=(?!N\/A)({user}[^=@]{1,2000}?)(@({domain}[^@]{1,2000}?))?(\t|\s{1,100}\w+=|\s{0,100}\||\s{0,100}$|\s{0,100}"{1,20}\s{0,100}$)""",
      """\WusrName =(?!N\/A)({user}[^=@]{1,2000}?)(@({domain}[^@]{1,2000}?))?(\t|\s{1,100}\w+=|\s{0,100}\||\s{0,100}$|\s{0,100}"{1,20}\s{0,100}$)""",
      """\Wdomain=(?!N\/A)({domain}[^=]{1,2000}?)(\t|\s{1,100}\w+=|\s{0,100}\||\s{0,100}$|\s{0,100}"{1,20}\s{0,100}$)""",
      """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\WsrcPort=({src_port}\d{1,100})""",
      """\WdstPort=({dest_port}\d{1,100})""",
      """\Wcat=({category}[^\|]{1,2000}?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """\Wproto=({protocol}[^\s]{1,2000}?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """\WfileName =({file_name}.+?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """\Wresource=({src_host}.+?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """\Wsev=({alert_severity}.+?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """CrowdStrike\|([^|]{1,2000}\|){2}({alert_name}[^|]{1,2000})""",
      """\Wurl=({additional_info}[^\|]{1,2000}?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """\Wmd5=({md5}[^\s]{1,2000}?)\s{0,100}(\||\w+=|$|"{1,20}\s{0,100}$)""",
      """({app}FalconHost)"""
    ]
  DupFields = [ "category->alert_type" ]}
```