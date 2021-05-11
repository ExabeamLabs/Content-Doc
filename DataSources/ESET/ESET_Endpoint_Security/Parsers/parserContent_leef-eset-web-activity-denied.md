#### Parser Content
```Java
{
Name = leef-eset-web-activity-denied
  DataType = "web-activity"
  Conditions = [ """LEEF:""", """|ESET|RemoteAdministrator|""", """cat=ESET Filtered Website Event""", """actionTaken=blocked""" ]
  Fields = ${ESETParserTemplates.eset-activity.Fields}[
  ]
}
eset-activity = {
    Vendor = ESET
    Product = ESET Endpoint Security
    Lms = Splunk
    TimeFormat = "MMM dd yyyy HH:mm:ss z"
    Fields = [
      """\WdevTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d [^\s]+)""",
      """dst=({dest_ip}[a-fA-F:\d.]+)""",
      """src=({src_ip}[a-fA-F:\d.]+)""",
      """srcPort=({src_port}\d{1,100})""",
      """dstPort=({dest_port}\d{1,100})""",
      """\|ESET\|(?:[^\|]+\|){2}({event_name}[^\|]+)""",
      """actionTaken=({action}[^=]+?)\s{0,100}(\w+=|$)""",
      """\Wresult=({outcome}[^=]+?)\s{0,100}(\w+=|$)""",
      """\Wdetail=({additional_info}[^.]+)\.""",
      """objectUri=({full_url}[^\s]+?)\s{0,100}(\w+=|$)""",
      """deviceName=({host}[^\s]+)""",
      """hash=({sha256}[^\s]+)""",
      """inbound=({direction}\d{1,100})""",
      """\Waction=({activity}[^\s]+)\s""",
      """\Wcat=({category}[^=]+?)\s{0,100}(\w+=|$)""",
      """\Wuser=({user}[^\s=]+?)\s{0,100}(\w+=|$)""",
      """processName=({process}({directory}(?:(\w+:)*([\\\/]+[^=\\\/"]+)+)?[\\\/]+)({process_name}[^=\,\\\/]+?))\s{0,100}(\w+=|$)""",
      """proto=({protocol}[^\s]+)""",
      """\Wuser '(({domain}[^\s\\]+)\\)?({user}[^\s]+)'.""",
      """accountName=(NT AUTHORITY\\+|({domain}[^\\]+?)\\+)?(SYSTEM|({user}[^=\s]+?))\s{0,100}(\w+=|$)"""
    ]

```