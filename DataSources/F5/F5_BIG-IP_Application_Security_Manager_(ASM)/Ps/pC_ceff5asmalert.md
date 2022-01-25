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
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wact=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs4=(N/A|({alert_name}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\Wapp=({protocol}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wrequest=({malware_url}.+?)\s{1,100}(\w+=|$)""",
    """\WexternalId=({alert_id}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """(\\r\\n|\s)(?i)User-Agent:\s{0,100}({user_agent}[^"]{1,2000}?)(\\r\\n[\w\-\.]{1,2000}:|")""",
    """(\\r\\n|\s)User-Agent:\s{0,100}Mozilla\/.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """CEF:([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}\d{1,100})""",
    """"username":"({user}[^"]{1,2000})""",
  ]
  DupFields = [ "browser->process" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "malware_url->malwareAttackerFile", "dest_ip->malwareAttackerIp", "alert_id->sourceId"]
    NameTemplate = """F5 Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address"]

}
```