#### Parser Content
```Java
{
Name = barracuda-email
    Vendor = Barracuda Email Security Gateway
  Product = Barracuda Email Security Gateway
    Lms = Syslog
    DataType = "dlp-email-alert"
    TimeFormat = "epoch_sec"
    Conditions = ["""Barracuda Networks""" , """Email Security Gateway"""]
    Fields = [
      """dvc=({host}[^\s]+)""",
      """rt=({time}[^\s]+)""",
      """src=({src_ip}[^\s]+)""",
      """act=({action}[^\s]+)""",
      """flexString1=({activity}[^\:]+):({outcome}\d+)"""
      """\|({alert_severity}[^\|]+)\|\s*event"""
      """suser=(-|({sender}[^\s]+))""",
      """duser=(-|({recipient}[^\s]+))"""
      """shost=(unknown|UNKNOWN|({external_domain}[^\s]+))""",
      """reason=({alert_name}\d+)""",
    ]
}

{
  Name = emp-app-activity
  Vendor = EMP
  Product = EMP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """EMP-LOGS""", """|ICALL|""" ]
  Fields = [
    """EMP-LOGS ([^\|]*\|)({location}[^\|]+)\|({app}[^\|]+)\|({host}[^\|]+)\|[^\|]*\|({user}[^\s\|]+)\|({activity}[^\|]+)\|({time}[^\|]+)\|(null|({object}[^\|]+))\|(null|({additional_info}[^\|]+))\|""",
  ]
  DupFields = [ "app->app_code" ]
}
```