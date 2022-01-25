#### Parser Content
```Java
{
Name = n-forwarded-cef-symantec-epp-alert
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = NitroCefSyslog
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "|310-2771385440|" ]
  Fields = [ 
    """\srt=({time}\d{1,100})""",
    """\|McAfee\|ESM\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_type}[^|]{1,2000}?)\|""",
    """\|McAfee\|ESM\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_severity}[^|]{1,2000}?)\|""",
    """\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sexternalId=({alert_id}\d{1,100})""",
    """\sshost=({src_host}.+?)\s{1,100}\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\snitroThreat_Name=({alert_name}.+?)\s{1,100}\w+=""",
    """\snitroDestination_Filename=({malware_url}.+?)\s{1,100}\w+="""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl"]
    NameTemplate = """Symantec Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```