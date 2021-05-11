#### Parser Content
```Java
{
Name = barracuda-email
    Vendor = Barracuda
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
      """flexString1=({activity}[^\:]+):({outcome}\d{1,100})"""
      """\|({alert_severity}[^\|]+)\|\s{0,100}event"""
      """suser=(-|({sender}[^\s]+))""",
      """duser=(-|({recipient}[^\s]+))"""
      """shost=(unknown|UNKNOWN|({external_domain}[^\s]+))""",
      """reason=({alert_name}\d{1,100})""",
    ]
}
```