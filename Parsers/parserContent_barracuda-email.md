#### Parser Content
```Java
{
Name = barracuda-email
    Vendor = Barracuda Email Security Gateway
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
```