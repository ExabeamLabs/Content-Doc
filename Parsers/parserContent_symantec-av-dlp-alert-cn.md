#### Parser Content
```Java
{
Name = symantec-av-dlp-alert-cn
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ "??????:", "??????:", "??????:", "??????:" ]
  Fields = [
    """\W??????:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d((\+|\-)\d\d:\d\d)?)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({host}[\w\-\.]+)\s*SymantecServer:""",
    """,??????:\s*({src_ip}[a-fA-F:\.\d]+),??????:\s*({src_port}\d+),??????:\s*({src_host}[\w\-\.]+),""",
    """,??????:\s*({dest_ip}[a-fA-F:\.\d]+),??????:\s*(|({dest_host}[\w\-\.]+)),??????:\s*({dest_port}\d+),""",
    """({protocol}[^,]+),({direction}[^,]+),??????:""",
    """\W????????????:\s*({process}.*[\\\/]({process_name}[^\\\/,]+))""",
    """\W??????:\s*({alert_name}[^,]+)""",
    """\W??????:\s*({outcome}[^,]+?)"*\s*$""",
    """\W??????:\s*({user}[^,]+),???:\s*({domain}[^,]+)"""
  ]
  DupFields = [ "alert_name->alert_type" ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "protocol->dlpProtocol", "src_host->dlpDeviceName", "outcome->dlpActionTaken"]
    NameTemplate = """Symantec DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```