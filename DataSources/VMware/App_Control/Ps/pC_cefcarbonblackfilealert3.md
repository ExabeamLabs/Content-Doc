#### Parser Content
```Java
{
Name = cef-carbonblack-file-alert-3
  Conditions = [ """CEF:""", """|VMware Carbon Black|App Control|""", """cat=""", """externalId=""" ]

cef-carbonblack-file-alert = {
  Vendor = VMware
  Product = App Control
  Lms = ArcSight
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\srt=({time}[\d]{1,2000})""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """dvc=({host_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}(\w+=|$)""",
    """dvchost=({host}[^=\s]{1,1000})\s{1,100}(\w+=|$)""",
    """dst=({dest_ip}[A-Fa-f:.\d]{1,2000})\s{1,100}(\w+=|$)""",
    """dhost=(([\w+\\]{1,10})\\{1,20})?({dest_host}[^\s=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """duser=((NT AUTHORITY|({domain}[^\\=]{1,2000}))\\{1,20})?(SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^\\=\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """externalId=({alert_id}[^\s=]{1,100})\s{1,100}(\w+=|$)""",
    """Carbon Black\|(Protection|App Control)\|([^|]{0,2000}\|){2}({alert_name}[^\|]{1,2000})\|""",
    """Carbon Black\|(Protection|App Control)\|([^|]{0,2000}\|){3}({alert_severity}[^\|]{1,2000})\|""",
    """cat=({alert_type}[^=]{1,2000})\s{1,100}(\w+=|$)""",
    """deviceProcessName =\s{0,20}({process}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """filePath=({file_path}(({file_parent}[^=]{1,2000}[^\\])\\{1,2000})?({file_name}[^=]{1,2000}))\s{1,100}(\w+=|$)""",
    """fname=({file_name}[^=]{1,2000})\s{1,100}(\w+=|$)""",
    """fileHash=({old_hash}[^=]{1,2000})\s{1,100}(\w+=)""",
    """msg=({additional_info}[^=]{1,2000}?)\s{1,100}(\w+=|$)"""
  
}
```