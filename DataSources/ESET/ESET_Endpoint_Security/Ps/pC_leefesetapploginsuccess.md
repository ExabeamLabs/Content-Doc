#### Parser Content
```Java
{
Name = leef-eset-app-login-success
  DataType = "app-login"
  Conditions = [ """LEEF:""", """|ESET|RemoteAdministrator|""", """cat=ESET RA Audit Event""", """Native user login""", """result=Success""" ]
  Fields = ${ESETParserTemplates.eset-activity.Fields}[
  ]
}
eset-activity = {
    Vendor = ESET
    Product = ESET Endpoint Security
    Lms = Splunk
    TimeFormat = "MMM dd yyyy HH:mm:ss z"
    Fields = [
      """\WdevTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d [^\s]{1,2000})""",
      """dst=({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """src=({src_ip}[a-fA-F:\d.]{1,2000})""",
      """srcPort=({src_port}\d{1,100})""",
      """dstPort=({dest_port}\d{1,100})""",
      """\|ESET\|(?:[^\|]{1,2000}\|){2}({event_name}[^\|]{1,2000})""",
      """actionTaken=({action}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """\Wresult=({outcome}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """\Wdetail=({additional_info}[^.]{1,2000})\.""",
      """objectUri=({full_url}[^\s]{1,2000}?)\s{0,100}(\w+=|$)""",
      """deviceName=({host}[^\s]{1,2000})""",
      """hash=({sha256}[^\s]{1,2000})""",
      """inbound=({direction}\d{1,100})""",
      """\Waction=({activity}[^\s]{1,2000})\s""",
      """\Wcat=({category}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """\Wuser=({user}[^\s=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """processName=({process}({directory}(?:(\w+:)*([\\\/]{1,2000}[^=\\\/"]{1,2000})+)?[\\\/]{1,2000})({process_name}[^=\,\\\/]{1,2000}?))\s{0,100}(\w+=|$)""",
      """proto=({protocol}[^\s]{1,2000})""",
      """\Wuser '(({domain}[^\s\\]{1,2000})\\)?({user}[^\s]{1,2000})'.""",
      """accountName=(NT AUTHORITY\\+|({domain}[^\\]{1,2000}?)\\+)?(SYSTEM|({user}[^=\s]{1,2000}?))\s{0,100}(\w+=|$)"""
    ]

```