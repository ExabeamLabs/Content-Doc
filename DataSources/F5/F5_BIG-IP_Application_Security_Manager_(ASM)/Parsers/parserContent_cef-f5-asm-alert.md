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
    """\Wrt=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wact=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs4=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """\Wapp=({protocol}.+?)\s{1,100}(\w+=|$)""",
    """\Wrequest=({malware_url}.+?)\s{1,100}(\w+=|$)""",
    """\WexternalId=({alert_id}.+?)\s{1,100}(\w+=|$)""",
    """(\\r\\n|\s)Host:\s{0,100}({domain}[^"]+?)((\\r\\n|\s{1,100})[\w\-]+:|")""",
    """(\\r\\n|\s)User-Agent:\s{0,100}({user_agent}[^"]+?)(\\r\\n[\w\-]+:|")""",
    """(\\r\\n|\s)User-Agent:\s{0,100}Mozilla\/.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
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