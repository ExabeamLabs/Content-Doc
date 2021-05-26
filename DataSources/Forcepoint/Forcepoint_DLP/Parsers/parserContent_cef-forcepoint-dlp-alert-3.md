#### Parser Content
```Java
{
Name = cef-forcepoint-dlp-alert-3
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "dd MMM'.' yyyy',' HH:mm:ss"
  Conditions = ["""|Forcepoint|Forcepoint DLP|""" , """|DLP Syslog|""", """caseClassification="""]
  Fields = [
     """caseDescription=({additional_info}({user_lastname}[^,<]{1,2000}),\s{0,100}({user_firstname}[^\s,]{1,2000}).+?)\scaseDate""",
     """caseDescription=({additional_info}({user}^((?!Unknown source).)*<.+?>).+?)\scaseDate""",
     """({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
     """caseDateAndTime=({time}\d\d\s{0,100}\w{3}\.\s{0,100}\d\d\d\d,\s{0,100}\d\d:\d\d:\d\d)""",
     """caseClassification=({alert_type}.+?)\s{0,100}numberOfI""",
     """riskScore=({alert_severity}[^\s]{1,2000})\s""",
     """content to\s{0,100}({target}[^\s]{1,2000})""",
     """sent.+?content.+?to\s{0,100}({target}.+?)\."""
     """content(\s\(.+?\))? to\s{0,100}({target}[^\s]{1,2000})(\sin|\.\s)""",
     """content(\s\(.+?\))? to\s{0,100}({target}printer\s{0,100}.+?)(\.|\sin\s)"""
     """to ({target}multiple destinations),""",
     """sent\s({file_name}.+?)\scontent""",
     """custom\s({file_name}.+?)\s(content|and)""",
     """sent more than .+? ({file_name}.+?)\sto"""
  ]
  DupFields = ["alert_type->alert_name"]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_type->description", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity","file_name->dlpFileName", "outcome->dlpActionTaken","host->dlpDeviceName"]
    NameTemplate = """Forcepoint DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="user", Name="user", Fields=["user->windows_id"]}
```