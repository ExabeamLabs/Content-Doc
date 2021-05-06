#### Parser Content
```Java
{
Name = leef-eset-network-alert
  DataType = "network-alert"
  Conditions = [ """LEEF:""", """|ESET|RemoteAdministrator|""", """cat=ESET Firewall Event""" ]
  Fields = ${ESETParserTemplates.eset-activity.Fields}[
    """eventDesc=({alert_name}[^=]+?)\s*(\w+=|$)""",
    """scannerID=({additional_info}[^=]+?)\s*(\w+=|$)""",
    """\Wsev=({alert_severity}\d+)"""
  ]
  DupFields = ["event_name->alert_type"]
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
      """srcPort=({src_port}\d+)""",
      """dstPort=({dest_port}\d+)""",
      """\|ESET\|(?:[^\|]+\|){2}({event_name}[^\|]+)""",
      """actionTaken=({action}[^=]+?)\s*(\w+=|$)""",
      """\Wresult=({outcome}[^=]+?)\s*(\w+=|$)""",
      """\Wdetail=({additional_info}[^.]+)\.""",
      """objectUri=({full_url}[^\s]+?)\s*(\w+=|$)""",
      """deviceName=({host}[^\s]+)""",
      """hash=({sha256}[^\s]+)""",
      """inbound=({direction}\d+)""",
      """\Waction=({activity}[^\s]+)\s""",
      """\Wcat=({category}[^=]+?)\s*(\w+=|$)""",
      """\Wuser=({user}[^\s=]+?)\s*(\w+=|$)""",
      """processName=({process}({directory}(?:(\w+:)*([\\\/]+[^=\\\/"]+)+)?[\\\/]+)({process_name}[^=\,\\\/]+?))\s*(\w+=|$)""",
      """proto=({protocol}[^\s]+)""",
      """\Wuser '(({domain}[^\s\\]+)\\)?({user}[^\s]+)'.""",
      """accountName=(NT AUTHORITY\\+|({domain}[^\\]+?)\\+)?(SYSTEM|({user}[^=\s]+?))\s*(\w+=|$)"""
    ]

```