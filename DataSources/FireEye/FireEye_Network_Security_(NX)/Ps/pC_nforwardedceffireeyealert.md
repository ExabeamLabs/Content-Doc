#### Parser Content
```Java
{
Name = n-forwarded-cef-fireeye-alert
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = NitroCefSyslog
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "|444-2835433003|" ]
  Fields = [ """\srt=({time}\d{1,100})""",
    """\|McAfee\|ESM\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_name}[^|]{1,2000}?)\|""",
    """\|McAfee\|ESM\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_severity}[^|]{1,2000}?)\|""",
    """\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sexternalId=({alert_id}\d{1,100})""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\snitroObjectID=({alert_type}.+?)\s{1,100}nitroAttacker_IP""",
    """\snitroURL=({additional_info}[^\r\n]{1,2000})\s{1,100}"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```