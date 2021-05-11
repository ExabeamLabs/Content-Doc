#### Parser Content
```Java
{
Name = cef-carbonblack-alert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Carbon Black|Carbon Black|""", """|reason=""", """dhost=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\|reason=({alert_type}.+?)\|({alert_name}.+?)\|({alert_severity}\d{1,100})?""",
    """\srt=({time}\d{1,100})""",
    """\sdhost=({src_host}[^\s]+)""",
    """\s(dst|local_ip)=({src_ip}[^\s]+)""",
    """\sdeviceSeverity=({alert_severity}\d{1,100})""",
    """\sdirection:({direction}(Inbound|Outbound))""",
    """\sremote_ip:({dest_ip}[A-Fa-f:\d.]+)""",
    """\salliance_link_[^\s:]+:({additional_info}[^\s]+)""",
    """\sfname=({malware_url}.+?)\s{1,100}\w+=""",
    """\sfname=({malware_url_path}\w+:\/\/.+?)\s{1,100}\w+=""",
    """\sfname=({file_path}(?!\w+:\/\/).+?)\s{1,100}\w+=""",
    """\sdvchost=({host}[^\s]+)""",
    """\sdproc=({process_name}.*?)\s\w+=""",
  ]
  DupFields = ["host->dest_host"]
  SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "alert_type->description", "malware_url_path->malwareAttackerUrl", "file_path->malwareAttackerFile", "dest_ip->malwareAttackerIp"]
      NameTemplate = """Carbon Black Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```