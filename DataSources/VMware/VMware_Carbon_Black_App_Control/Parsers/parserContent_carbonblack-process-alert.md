#### Parser Content
```Java
{
Name = carbonblack-process-alert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Direct
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Cb Protection event:""", """subtype="Execution block""", """ process=""" ]
  Fields = [
    """({host}[\w.\-]+)\s(\-\s)+Cb Protection event:"""
    """\sdate="({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """\stext="({additional_info}[^"]+)"""",
    """\ssubtype="({event_code}[^"]+)"""",
    """\shostname="(({domain}[^"\\]+)\\)?({dest_host}[^"\\]+)"""",
    """\susername="(({domain}[^"\\]+)\\)?({user}[^"\\]+)"""",
    """\sip_address="({dest_ip}[a-fA-F\d.:]+)""",
    """\sprocess="({process}(({directory}[^"]+?)\\)?({process_name}[^"\\]+?))"""",
    """\sfile_hash="({md5}[^"]+)"""",
    """\srule_name="({alert_name}[^"]+)"""",
    """\sprocess_threat="({alert_severity}[^"]+)"""",
    """\sfile_hash="({md5}[^"]+)"""",
    """\sfile_path="({file_path}[^"]+)"""",
    """\sfile_name="({file_name}[^"]+)"""",
  ]
  DupFields = [ "event_code->alert_type","directory->process_directory" ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]}
```