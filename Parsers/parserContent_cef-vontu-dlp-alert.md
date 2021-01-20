#### Parser Content
```Java
{
Name = cef-vontu-dlp-alert
  Vendor = Symantec
  Product = Symantec DLP
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Vontu|Monitor""", """catdt=Content Security""" ]
  Fields = [
    """([^\|]*\|){5}({alert_name}[^\|]+)""",
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\WeventId=({alert_id}\d+)""",
    """\Wmsg=({alert_type}.+?)\s*(\w+=|$)""",
    """\WdeviceSeverity=({alert_severity}\d+)""",
    """\WsourceDnsDomain=({domain}.+?)\s*(\w+=|$)""",
    """\Wcs1=(?:({user}[^\s]+?)|({user_fullname}\w+(?:\s+\w+)+))(\s+\w+=|\s*$)""",
    """\Wsuser=(?:N\/A|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({user_email}[^\s@]+@[^\s@]+))""",
    """\Wsuser=\w+:\/+({domain}[^\/\\=]+)[\\\/]+(?:({user}[^\\\/\s]+?)|({user_fullname}\w+(?:\s+\w+)+))(\s+\w+=|\s*$)""",
    """\WdestinationDnsDomain=({top_domain}.+?)\s*(\w+=|$)""",
    """\Wduser=(?:N\/A|({target}.+?))\s*(\w+=|$)""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wshost=(?:N\/A|({src_host}.+?))\s*(\w+=|$)""",
    """\Wfname=(?:N\/A|({file_name}.+?))\s*(\w+=|$)""",
    """\Wcs2=(None|({action}.+?))(\s+\w+=|\s*$)""",
    """\Wrequest=(unknown|N/A|({target}.+?))(\s+\w+=|\s*$)""",
    """\Wapp=(|({protocol}.+?))(\s+\w+=|\s*$)""",
    """\Wcs4=(|({subject}.+?))(\s+\w+=|\s*$)""",
  ]
  DupField;s = ["user_email->sender", "target->recipients"]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "host->dlpDeviceName", "file_name->dlpFileName", "alert_type->dlpActionTaken"]
    NameTemplate = """Vontu DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```