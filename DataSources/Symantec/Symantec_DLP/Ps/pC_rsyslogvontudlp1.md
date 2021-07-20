#### Parser Content
```Java
{
Name = r-syslog-vontu-dlp-1
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """/ProtectManager/IncidentDetail.do""", """^^""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """({host}[\w.\-]{1,2000})\s{1,100}({alert_name}[^\s\^]{1,2000})\^\^({alert_id}\d{1,100})\^\^({additional_info}[^\^]{1,2000})\^\^[^\^]{0,2000}\^\^({recipients}({recipient}[^\^,]{1,2000})[^\^]{0,2000})\^\^({sender}[^\^]{1,2000})\^\^({alert_severity}[^\^]{1,2000})\^\^({subject}[^\^]{1,2000})\^\^(N/A|({object}[^\^]{1,2000}))\^\^([^\^]{0,2000}\^\^){9}({protocol}[^\^]{1,2000}?)\s{0,100}(\^|$)""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}({outcome}[^\^]{1,2000}?)\^\^""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]{1,2000}\s{1,100}[^\^]{0,2000}?\^\^({alert_id}[^\^]{1,2000})""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]{1,2000}\s{1,100}([^\^]{0,2000}?\^\^){2}({additional_info}[^\^]{1,2000})""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}([^\^]{0,2000}?\^\^){4}({recipients}({recipient}[^\^,]{1,2000})[^\^]{0,2000})""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]{1,2000}\s{1,100}([^\^]{0,2000}?\^\^){5}({sender}[^\^]{1,2000})""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]{1,2000}\s{1,100}([^\^]{0,2000}?\^\^){6}({alert_severity}[^\^]{1,2000})""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]{1,2000}\s{1,100}([^\^]{0,2000}?\^\^){7}({subject}[^\^]{1,2000})""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]{1,2000}\s{1,100}([^\^]{0,2000}?\^\^){13}({alert_name}[^\^]{1,2000})""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]{1,2000}\s{1,100}([^\^]{0,2000}?\^\^){14}({alert_type}[^\^]{1,2000})""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]{1,2000}\s{1,100}([^\^]{0,2000}?\^\^){18}({protocol}[^\^]{1,2000}?)\s{0,100}(\^|$)""",
    """\^\^\?{3}\s{0,100}({outcome}\S+)""",
  ]
  DupFields = [ "sender->user_email", "sender->original_user" ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user_email->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "outcome->dlpActionTaken"]
    NameTemplate = """Vontu DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="user", Name="windows_id", Fields=["user_email->windows_id"]}
```