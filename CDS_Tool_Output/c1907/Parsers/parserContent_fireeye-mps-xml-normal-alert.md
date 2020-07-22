#### Parser Content
```Java
{
Name = fireeye-mps-xml-normal-alert
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """msg="normal""","""product="Web MPS"""","""<src vlan=""" ]
  Fields = [
             """<occurred>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
             """exabeam_host=({host}\S+)""",
             """ fenotify-({alert_id}\d+)""",
             """<alert id="({alert_id}[^"]+)""",
             """<src vlan=\".+\">\s*<ip>({src_ip}[\d\.]+)""",
             """<src .+?<host>({src_host}[^<]+)""",
             """xsi:schemaLocation=.+?name="({alert_type}[^"]+)".*severity="({alert_severity}[^"]+)"""",
             """<malware name="({alert_name}[^"]+)"""",
             """<dst>.+?<ip>({dest_ip}[^<]+)</ip""",
        ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```