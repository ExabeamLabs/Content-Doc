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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({host}\S+)\s{1,100}(\S+\s{1,100}){4}EventName=""",
    """\sAlertTime=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sOS=({os}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sSeverity=({alert_severity}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sRuleName=({alert_name}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sAlertID=({alert_id}\d{1,100})""",
    """\sAlertDetailsURL=({additional_info}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sSessionID=({session_id}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sServerName=({dest_host}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sDomainName=({domain}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sUserName=(?:n\/a|({user}[^;]+?))\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sLoginName=({user}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientName=(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[^;]+?))\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientAddress=({src_ip}[a-fA-F\d.:]+)""",
    """\sApplicationName=({alert_type}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sWindowTitle=({target}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sProcessName=({process}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
  ]
}
```