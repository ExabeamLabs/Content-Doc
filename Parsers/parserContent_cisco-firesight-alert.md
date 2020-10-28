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
    """\Wevent_sec=({time}\d+)""",
    """\Wevent_id=({alert_id}\d+)""",
    """\W(msg|corr_rule)=\\?"?({alert_name}[^"\\=]+)\\?"?\s+\w+=""",
    """\W(class_desc|corr_policy)=\\?"?({alert_type}[^"\\=]+)\\?"?\s+\w+=""",
    """\Wpriority=({alert_severity}[^\s]+)""",
    """\Wsrc_ip=(0|0.0.0.0|({src_ip}[A-Fa-f:\d.]+))""",
    """\Wdest_ip=(0|0.0.0.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\d\d:\d\d:\d\d\s+({host}[\w-]+)\s"""
  ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Cisco Firesight Alert ${alert_type} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```