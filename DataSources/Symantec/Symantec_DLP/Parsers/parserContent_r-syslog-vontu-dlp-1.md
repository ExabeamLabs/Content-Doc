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
    """({host}[\w.\-]+)\s{1,100}({alert_name}[^\s\^]+)\^\^({alert_id}\d{1,100})\^\^({additional_info}[^\^]+)\^\^[^\^]*\^\^({recipients}({recipient}[^\^,]+)[^\^]*)\^\^({sender}[^\^]+)\^\^({alert_severity}[^\^]+)\^\^({subject}[^\^]+)\^\^(N/A|({object}[^\^]+))\^\^([^\^]*\^\^){9}({protocol}[^\^]+?)\s{0,100}(\^|$)""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]+)\s{1,100}({outcome}[^\^]+?)\^\^""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]+\s{1,100}[^\^]*?\^\^({alert_id}[^\^]+)""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]+\s{1,100}([^\^]*?\^\^){2}({additional_info}[^\^]+)""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]+)\s{1,100}([^\^]*?\^\^){4}({recipients}({recipient}[^\^,]+)[^\^]*)""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]+\s{1,100}([^\^]*?\^\^){5}({sender}[^\^]+)""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]+\s{1,100}([^\^]*?\^\^){6}({alert_severity}[^\^]+)""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]+\s{1,100}([^\^]*?\^\^){7}({subject}[^\^]+)""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]+\s{1,100}([^\^]*?\^\^){13}({alert_name}[^\^]+)""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]+\s{1,100}([^\^]*?\^\^){14}({alert_type}[^\^]+)""",
    """\d\d:\d\d:\d\d\s{1,100}[\w.\-]+\s{1,100}([^\^]*?\^\^){18}({protocol}[^\^]+?)\s{0,100}(\^|$)""",
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