#### Parser Content
```Java
{
Name = cef-fireeye-ex-security-alert
  Vendor = FireEye
  Product = FireEye Email Security (EX)
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|FireEye|""", """flexString2Label=subject""", """|CMS|""", """fileType=""" ]
  Fields = [
     """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """rt=({time}[a-zA-Z]{3} \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
     """act=({action}[^=]{1,2000}?)\s{0,100}\w+=""",
     """externalId=({alert_id}\d{1,100})""",
     """\|FireEye\|([^\|]{1,2000}\|){3}({alert_name}[^\|]{1,2000})\|""",
     """\scs1Label=sname cs1=({alert_name}[^\s]{1,2000})""",
     """\|FireEye\|([^\|]{1,2000}\|){3}({alert_type}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})\|""",
     """\sdhost=({dest_host}\S+)""",
     """\scs5Label=cncHost cs5=(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]{1,2000}))""",
     """\sdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
     """\sfname=(?:[^,]{1,2000},)?\s{0,100}({file_name}.+?)\s{0,100}(?:\w+=|$)""",
     """\sfname=({file_name}[^=]{1,2000}?)\s{0,100}(?:\w+=|$)""",
     """\sdvc=({host}[A-Fa-f:\d.]{1,2000})""",
     """\sdvchost=({host}[^\s]{1,2000})""",
     """\ssrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
     """\sduser=({user}[^@]{1,2000})(@[^\s]{1,2000})?\s{1,100}cn1Label""",
     """\sduser=({user_email}[^@\s]{1,2000}@[^,\s]{1,2000})"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "malware_file_name->malwareAttackerFile", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```