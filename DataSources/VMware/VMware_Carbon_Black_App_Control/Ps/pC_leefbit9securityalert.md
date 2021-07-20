#### Parser Content
```Java
{
Name = leef-bit9-security-alert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Conditions = [ """|Bit9|Security_Platform|""", """|cat=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """\WdevTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """LEEF:([^\|]{0,2000}\|){4}({alert_name}[^\|]{1,2000})""",
    """({host}[\w\-.]{1,2000})\s{0,100}LEEF:""",
    """\Wsev=({alert_severity}\d{1,100})""",
    """\WusrName=(({domain}[^\\]{1,2000})\\+)?({user}\S+)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """\WsrcHostName=(({domain}[^\\]{1,2000})\\+)?({src_host}[\w\-.]{1,2000})""",
    """\WdstHostName=({dest_host}[\w\-.]{1,2000})""",
    """\WsrcProcess=({process}({directory}([^=]{1,2000})?[\\\/])?({process_name}[^\\\/=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\WfilePath=({file_path}.+?)\s{0,100}(\w+=|$)""",
    """\WfileName=({file_name}.+?)\s{0,100}(\w+=|$)""",
    """\WinstallerFileName=({additional_info}.+?)\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "alert_name->alert_type","directory->process_directory" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName",  "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "alert_type->description", "file_path->malwareAttackerFile"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```