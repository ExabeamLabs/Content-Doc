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
    """\|rt=({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s{1,100}CEF:""",
    """\d\d:\d\d\s({host}[^\s]+)\sVaronis-DatAlert:""",
    """\sdvchost=(?:|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))\s\w+=""",
    """\sduser=(?:|((Abstract|({domain}[^\\]+))\\+)?(Nobody|SYSTEM|({user}[^\\\s,]+?)))\s{1,100}\w+=""",
    """\sduser=(?:|((Abstract|({domain}[^\\]+))\\+)?(Nobody|SYSTEM|({user_fullname}[^\\\s,=]+\s{1,100}[^\\,=]+?)))\s{1,100}\w+=""",
    """\sduser=(?:|(({domain}[^\\]+)\\+)?({user_lastname}[^\\,=]+?),\s{0,100}({user_firstname}[^\\,=]+))\s{1,100}\w+=""",
    """\|Varonis Inc.\|([^|]*\|){3}({accesses}[^|]+)\|""",
    """\Wact=({accesses}.+?)\s{1,100}(\w+=|$)""",
    """\scs2=\s{0,100}(?:|({alert_name}.+?))(\s{1,100}likely|\s{1,100}\w+=)""",
    """\sfilePath=(?:|({additional_info}.+?))\s{1,100}\w+=""",
    """\s(fname|filePath)=({file_path}({file_parent}[^=]*?[\\\/]+)?({file_name}[^\\\/=]+?(\.({file_ext}\w+))?))\s{1,100}\w+=""",
    """\sdhost=(?:|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))\s{1,100}\w+=""",
    """\soutcome=(?:|({outcome}.+?))\s{1,100}\w+=""",
    """\|Varonis Inc.\|([^\|]+\|){4}({alert_severity}\d{1,100})\|"""
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