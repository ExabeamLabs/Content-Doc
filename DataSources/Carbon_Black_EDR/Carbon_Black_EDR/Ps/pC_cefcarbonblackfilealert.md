#### Parser Content
```Java
{
Name = cef-carbonblack-file-alert
  Product = Carbon Black EDR
  Conditions = [ """CEF:""", """|Carbon Black|Protection|""", " fname=" ]
  DupFields = ["old_hash->new_hash"]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]

}
```