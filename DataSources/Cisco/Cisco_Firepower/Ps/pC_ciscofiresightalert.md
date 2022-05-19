#### Parser Content
```Java
{
Name = cisco-firesight-alert
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """sec_zone_ingress=""","""impact_bits=""" ]
  Fields = [
    """\Wevent_sec=({time}\d{1,100})""",
    """\Wevent_id=({alert_id}\d{1,100})""",
    """\W(msg|corr_rule)=\\?"?({alert_name}[^"\\=]{1,2000})\\?"?\s{1,100}\w+=""",
    """\W(class_desc|corr_policy)=\\?"?({alert_type}[^"\\=]{1,2000})\\?"?\s{1,100}\w+=""",
    """\Wpriority=({alert_severity}[^\s]{1,2000})""",
    """\Wsrc_ip=(0|0.0.0.0|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\Wdest_ip=(0|0.0.0.0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[\w-]{1,2000})\s"""
    """\suser=\\?"{0,20}(0|No Authentication Required|({user}[^\s"]{1,2000}))""",
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Cisco Firesight Alert ${alert_type} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]

}
```