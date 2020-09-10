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
     """caseDescription=({additional_info}({user_lastname}[^,<]+),\s*({user_firstname}[^\s,]+).+?)\scaseDate""",
     """caseDescription=({additional_info}({user}^((?!Unknown source).)*<.+?>).+?)\scaseDate""",
     """({host}[\w\-.]+)\s+CEF:""",
     """caseDateAndTime=({time}\d\d\s*\w{3}\.\s*\d\d\d\d,\s*\d\d:\d\d:\d\d)""",
     """caseClassification=({alert_type}.+?)\s*numberOfI""",
     """riskScore=({alert_severity}[^\s]+)\s""",
     """content to\s*({target}[^\s]+)""",
     """sent.+?content.+?to\s*({target}.+?)\."""
     """content(\s\(.+?\))? to\s*({target}[^\s]+)(\sin|\.\s)""",
     """content(\s\(.+?\))? to\s*({target}printer\s*.+?)(\.|\sin\s)"""
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