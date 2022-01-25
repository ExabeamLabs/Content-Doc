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
      """dvc=({host}[^\s]{1,2000})""",
      """rt=({time}[^\s]{1,2000})""",
      """src=({src_ip}[^\s]{1,2000})""",
      """act=({action}[^\s]{1,2000})""",
      """flexString1=({activity}[^\:]{1,2000}):({outcome}\d{1,100})"""
      """\|({alert_severity}[^\|]{1,2000})\|\s{0,100}event"""
      """suser=(-|({sender}[^\s]{1,2000}))""",
      """duser=(-|({recipient}[^\s]{1,2000}))"""
      """shost=(unknown|UNKNOWN|({external_domain}[^\s]{1,2000}))""",
      """reason=({alert_name}\d{1,100})""",
    ]


}
```