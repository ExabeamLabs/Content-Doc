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
    """([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\Wmsg=({alert_type}.+?)\s{0,100}(\w+=|$)""",
    """\WdeviceSeverity=({alert_severity}\d{1,100})""",
    """\WsourceDnsDomain=({domain}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs1=(?:({user}[^\s]{1,2000}?)|({user_fullname}\w+(?:\s{1,100}\w+)+))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(?:N\/A|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({user_email}[^\s@]{1,2000}@[^\s@]{1,2000}))""",
    """\Wsuser=\w+:\/+({domain}[^\/\\=]{1,2000})[\\\/]{1,2000}(?:({user}[^\\\/\s]{1,2000}?)|({user_fullname}\w+(?:\s{1,100}\w+)+))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdestinationDnsDomain=({top_domain}.+?)\s{0,100}(\w+=|$)""",
    """\Wduser=(?:N\/A|({target}.+?))\s{0,100}(\w+=|$)""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wshost=(?:N\/A|({src_host}.+?))\s{0,100}(\w+=|$)""",
    """\Wfname=(?:N\/A|({file_name}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs2=(None|({action}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrequest=(unknown|N/A|({target}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wapp=(|({protocol}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs4=(|({subject}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
  DupFields = ["user_email->sender", "target->recipients"]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "host->dlpDeviceName", "file_name->dlpFileName", "alert_type->dlpActionTaken"]
    NameTemplate = """Vontu DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```