#### Parser Content
```Java
{
Name = symantec-av-dlp-alert-cn
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ "本地:", "远程:", "规则:", "操作:" ]
  Fields = [
    """\W开始:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d((\+|\-)\d\d:\d\d)?)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({host}[\w\-\.]+)\s*SymantecServer:""",
    """,本地:\s*({src_ip}[a-fA-F:\.\d]+),本地:\s*({src_port}\d+),本地:\s*({src_host}[\w\-\.]+),""",
    """,远程:\s*({dest_ip}[a-fA-F:\.\d]+),远程:\s*(|({dest_host}[\w\-\.]+)),远程:\s*({dest_port}\d+),""",
    """({protocol}[^,]+),({direction}[^,]+),开始:""",
    """\W应用程序:\s*({process}.*[\\\/]({process_name}[^\\\/,]+))""",
    """\W规则:\s*({alert_name}[^,]+)""",
    """\W操作:\s*({outcome}[^,]+?)"*\s*$""",
    """\W用户:\s*({user}[^,]+),域:\s*({domain}[^,]+)"""
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