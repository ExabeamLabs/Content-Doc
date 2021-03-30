#### Parser Content
```Java
{
Name = varonis-dlp-alert-1
  Vendor = Varonis
  Product = Data Security Platform
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Varonis Inc.|""", """|DatAdvantage|""", """cat=Alert""" ]
  Fields = [
    """\|rt=({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s+CEF:""",
    """\d\d:\d\d\s({host}[^\s]+)\sVaronis-DatAlert:""",
    """\sdvchost=(?:|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))\s\w+=""",
    """\sduser=(?:|((Abstract|({domain}[^\\]+))\\+)?(Nobody|SYSTEM|({user}[^\\\s,]+?)))\s+\w+=""",
    """\sduser=(?:|((Abstract|({domain}[^\\]+))\\+)?(Nobody|SYSTEM|({user_fullname}[^\\\s,=]+\s+[^\\,=]+?)))\s+\w+=""",
    """\sduser=(?:|(({domain}[^\\]+)\\+)?({user_lastname}[^\\,=]+?),\s*({user_firstname}[^\\,=]+))\s+\w+=""",
    """\|Varonis Inc.\|([^|]*\|){3}({accesses}[^|]+)\|""",
    """\Wact=({accesses}.+?)\s+(\w+=|$)""",
    """\scs2=\s*(?:|({alert_name}.+?))(\s+likely|\s+\w+=)""",
    """\sfilePath=(?:|({additional_info}.+?))\s+\w+=""",
    """\s(fname|filePath)=({file_path}({file_parent}[^=]*?[\\\/]+)?({file_name}[^\\\/=]+?(\.({file_ext}\w+))?))\s+\w+=""",
    """\sdhost=(?:|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))\s+\w+=""",
    """\soutcome=(?:|({outcome}.+?))\s+\w+=""",
    """\|Varonis Inc.\|([^\|]+\|){4}({alert_severity}\d+)\|"""
  ]
    DupFields = [ "alert_name->alert_type" ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_type->description", "user->dlpUser", "alert_name->dlpPolicy", "file_name->dlpFileName", "host->dlpDeviceName"]
    NameTemplate = """Varonis DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address","dest_host->host_name"]}
```