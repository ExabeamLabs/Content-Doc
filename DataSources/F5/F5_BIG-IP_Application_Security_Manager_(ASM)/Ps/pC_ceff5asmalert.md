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
    """rt=({time}\w{1,100}\s{1,100}\d\d\s{1,100}\d\d\d\d\s{1,100}\d\d:\d\d:\d\d)""",
    """dvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """dvchost=({host}[\w\-.]{1,2000})""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """spt=({src_port}\d{1,100})""",
    """dpt=({dest_port}\d{1,100})""",
    """act=({outcome}[^\s]{1,2000})\s{1,100}(\w{1,100}=|$)""",
    """cs4=(N/A|({alert_name}[^=]{1,2000}))\s{1,100}(\w{1,100}=|$)""",
    """app=({protocol}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
    """request=({malware_url}[^\s]{1,2000})\s{1,100}(\w{1,100}=|$)""",
    """externalId=({alert_id}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
    """User-Agent:\s{1,100}({user_agent}[^"]{1,2000}?)\\r\\n""",
    """CEF:([^\|]{1,2000}\|){4}(\d{1,100}\|)?({alert_type}[^\|]{1,2000})""",
    """CEF:([^\|]{1,2000}\|){6}({alert_severity}\d{1,100})""",
    """"username":"({user}[^"]{1,2000})"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "malware_url->malwareAttackerFile", "dest_ip->malwareAttackerIp", "alert_id->sourceId"]
    NameTemplate = """F5 Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address"]

}
```