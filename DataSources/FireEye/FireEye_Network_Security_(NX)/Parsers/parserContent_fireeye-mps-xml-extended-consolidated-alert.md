#### Parser Content
```Java
{
Name = fireeye-mps-xml-extended-consolidated-alert
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """msg="extended""","""product="Web MPS"""","""</ip>""" ]
  Fields = [
             """<occurred>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
             """exabeam_host=({host}\S+)""",
             """ fenotify-({alert_id}\d{1,100})""",
             """<alert id="({alert_id}[^"]{1,2000})""",
             """<src vlan=\".+\">\s{0,100}<ip>({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """<src .+?<host>({src_host}[^<]{1,2000})""",
             """xsi:schemaLocation=.+?name="({alert_type}[^"]{1,2000})".*severity="({alert_severity}[^"]{1,2000})"""",
             """<malware name="({alert_name}[^"]{1,2000})"""",
             """<dst>.+?<ip>({dest_ip}[^<]{1,2000})</ip""",
        ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```