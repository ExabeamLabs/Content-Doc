#### Parser Content
```Java
{
Name = leef-bit9-security-alert
  Vendor = Carbon Black
  Product = CB Protection
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Conditions = [ """|Bit9|Security_Platform|""", """|cat=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """\WdevTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """LEEF:([^\|]*\|){4}({alert_name}[^\|]+)""",
    """({host}[\w\-.]+)\s*LEEF:""",
    """\Wsev=({alert_severity}\d+)""",
    """\WusrName=(({domain}[^\\]+)\\+)?({user}\S+)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
    """\WsrcHostName=(({domain}[^\\]+)\\+)?({src_host}[\w\-.]+)""",
    """\WdstHostName=({dest_host}[\w\-.]+)""",
    """\WsrcProcess=({process}({directory}([^=]+)?[\\\/])?({process_name}[^\\\/=]+?))\s*(\w+=|$)""",
    """\WfilePath=({file_path}.+?)\s*(\w+=|$)""",
    """\WfileName=({file_name}.+?)\s*(\w+=|$)""",
    """\WinstallerFileName=({additional_info}.+?)\s*(\w+=|$)""",
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