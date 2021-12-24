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
    """\|rt=({time}\w{3} \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]{1,2000})\s{1,100}CEF:""",
    """\d\d:\d\d\s({host}[^\s]{1,2000})\sVaronis-DatAlert:""",
    """\sdvc=({dest_ip}[A-Fa-f.\d:]{1,2000})""",
    """\sdvchost=(?:|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]{1,2000}))\s\w{1,2000}=""",
    """\sduser=(?:|((Abstract|({domain}[^\\]{1,2000}))\\+)?(Nobody|SYSTEM|({user}[^\\\s,]{1,2000}?)))\s{1,100}\w{1,2000}=""",
    """\sduser=(?:|((Abstract|({domain}[^\\]{1,2000}))\\+)?(Nobody|SYSTEM|({user_fullname}[^\\\s,=]{1,2000}\s{1,100}[^\\,=]{1,2000}?)))\s{1,100}\w{1,2000}=""",
    """\sduser=(?:|(({domain}[^\\]{1,2000})\\+)?({user_lastname}[^\\,=]{1,2000}?),\s{0,100}({user_firstname}[^\\,=]{1,2000}))\s{1,100}\w{1,2000}=""",
    """\|Varonis Inc.\|([^|]{0,2000}\|){3}({accesses}[^|]{1,2000})\|""",
    """\Wact=({accesses}[^=]{1,2000}?)\s{1,100}(\w{1,2000}=|$)""",
    """\scs2=\s{0,100}(?:|({alert_name}.+?))(\s{1,100}likely|\s{1,100}\w{1,2000}=)""",
    """\sfilePath=(?:|({additional_info}.+?))\s{1,100}\w{1,2000}=""",
    """\s(fname|filePath)=({file_path}({file_parent}[^=]{0,2000}?[\\\/]{1,2000})?({file_name}[^\\\/=]{1,2000}?(\.({file_ext}\w{1,2000}))?))\s{1,100}\w{1,2000}=""",
    """\sdhost=(?:|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]{1,2000}))\s{1,100}\w{1,2000}=""",
    """\soutcome=(?:|({outcome}\S{1,2000}?))\s{1,100}\w{1,2000}=""",
    """\|Varonis Inc.\|([^\|]{1,2000}\|){4}({alert_severity}\d{1,100})\|""",
    """SAMAccountName =(SYSTEM|not available|({user}[^#\s]{1,2000}))"""

  ]
    DupFields = [ "alert_name->alert_type" ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_type->description", "user->dlpUser", "alert_name->dlpPolicy", "file_name->dlpFileName", "host->dlpDeviceName"]
    NameTemplate = """Varonis DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="dest_address", Fields=["dest_ip->ip_address","dest_host->host_name"]

}
```