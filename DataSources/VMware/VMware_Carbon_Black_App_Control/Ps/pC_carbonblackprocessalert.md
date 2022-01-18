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
    """({host}[\w.\-]{1,2000})\s(\-\s)+Cb Protection event:"""
    """\sdate="({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """\stext="({additional_info}[^"]{1,2000})"""",
    """\ssubtype="({event_code}[^"]{1,2000})"""",
    """\shostname="(({domain}[^"\\]{1,2000})\\)?({dest_host}[^"\\]{1,2000})"""",
    """\susername="(({domain}[^"\\]{1,2000})\\)?({user}[^"\\]{1,2000})"""",
    """\sip_address="({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sprocess="({process}(({directory}[^"]{1,2000}?)\\)?({process_name}[^"\\]{1,2000}?))"""",
    """\sfile_hash="({md5}[^"]{1,2000})"""",
    """\srule_name="({alert_name}[^"]{1,2000})"""",
    """\sprocess_threat="({alert_severity}[^"]{1,2000})"""",
    """\sfile_hash="({md5}[^"]{1,2000})"""",
    """\sfile_path="({file_path}[^"]{1,2000})"""",
    """\sfile_name="({file_name}[^"]{1,2000})"""",
  ]
  DupFields = [ "event_code->alert_type","directory->process_directory" ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="dest_address", Fields=["dest_ip->ip_address", "dest_host->host_name"]

}
```