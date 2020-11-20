#### Parser Content
```Java
{
Name = cef-f5-asm-alert
  Vendor = F5
  Product = F5 BIG-IP Application Security Manager (ASM)
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """ ASM:""", """|F5|ASM|""", """HTTP""" ]
  Fields = [
    """\Wrt=({time}\w+\s+\d+\s+\d+\s+\d+:\d+:\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wact=({outcome}.+?)\s+(\w+=|$)""",
    """\Wcs4=({alert_name}.+?)\s+(\w+=|$)""",
    """\Wapp=({protocol}.+?)\s+(\w+=|$)""",
    """\Wrequest=({malware_url}.+?)\s+(\w+=|$)""",
    """\WexternalId=({alert_id}.+?)\s+(\w+=|$)""",
    """(\\r\\n|\s)Host:\s*({domain}[^"]+?)((\\r\\n|\s+)[\w\-]+:|")""",
    """(\\r\\n|\s)User-Agent:\s*({user_agent}[^"]+?)(\\r\\n[\w\-]+:|")""",
    """(\\r\\n|\s)User-Agent:\s*Mozilla\/.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """CEF:([^\|]*\|){4}({alert_type}[^\|]+)""",
  ]
  DupFields = [ "browser->process" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "malware_url->malwareAttackerFile", "dest_ip->malwareAttackerIp", "alert_id->sourceId"]
    NameTemplate = """F5 Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```