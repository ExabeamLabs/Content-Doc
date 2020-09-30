#### Parser Content
```Java
{
Name = cef-carbonblack-alert
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Carbon Black|Carbon Black|""", """|reason=""", """dhost=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\|reason=({alert_type}.+?)\|({alert_name}.+?)\|({alert_severity}\d+)?""",
    """\srt=({time}\d+)""",
    """\sdhost=({src_host}[^\s]+)""",
    """\s(dst|local_ip)=({src_ip}[^\s]+)""",
    """\sdeviceSeverity=({alert_severity}\d+)""",
    """\sdirection:({direction}(Inbound|Outbound))""",
    """\sremote_ip:({dest_ip}[A-Fa-f:\d.]+)""",
    """\salliance_link_[^\s:]+:({additional_info}[^\s]+)""",
    """\sfname=({malware_url}.+?)\s+\w+=""",
    """\sfname=({malware_url_path}\w+:\/\/.+?)\s+\w+=""",
    """\sfname=({file_path}(?!\w+:\/\/).+?)\s+\w+=""",
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