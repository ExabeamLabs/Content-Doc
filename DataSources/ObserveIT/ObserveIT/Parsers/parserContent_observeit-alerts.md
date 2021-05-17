#### Parser Content
```Java
{
Name = observeit-alerts
  Vendor = ObserveIT
  Product = ObserveIT
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """EventName=ObserveIT-Alerts;""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}\S+)\s{1,100}(\S+\s{1,100}){4}EventName=""",
    """\sAlertTime=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sOS=({os}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sSeverity=({alert_severity}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sRuleName=({alert_name}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sAlertID=({alert_id}\d{1,100})""",
    """\sAlertDetailsURL=({additional_info}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sSessionID=({session_id}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sServerName=({dest_host}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sDomainName=({domain}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sUserName=(?:n\/a|({user}[^;]{1,2000}?))\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sLoginName=({user}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientName=(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[^;]{1,2000}?))\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientAddress=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sApplicationName=({alert_type}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sWindowTitle=({target}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sProcessName=({process}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
  ]
}
```