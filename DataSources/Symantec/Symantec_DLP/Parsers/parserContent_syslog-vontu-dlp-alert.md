#### Parser Content
```Java
{
Name = syslog-vontu-dlp-alert
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Direct
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """incident_id="""", """, blocked="""", """, policy="""", """, recipients="""", """, sender="""", """, severity="""", """, subject="""" ]
    Fields = [
    """exabeam_host=({host}\S+)""",
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """({host}[\w\.-]+)\s{1,100}incident_id""",
      """[\s,]incident_id="{1,20}({alert_id}\d{1,100})""",
      """[\s,]blocked="{1,20}(None|({outcome}[^"]+?))"""",
      """[\s,]policy="{1,20}({alert_name}[^"]+?)"""",
      """[\s,]occurred_on="{1,20}({occured_time}[^"]+?)"""",
      """[\s,]reported_on="{1,20}({reported_time}[^"]+?)"""",
      """[\s,]policy="{1,20}({alert_type}[^"]+?)"""",
      """[\s,]rules=(?:"{1,20})?\s{0,100}({alert_type}[^="]+?)\s{0,100}(?:"{1,20})?,\s\w+=""",
      """[\s,]severity="{1,20}({alert_severity}[^"]+?)"""",
      """[\s,]sender="{1,20}\s{0,100}({sender}[^\s"@,]+@[^\s"@,]+?)"""",
      """,\sendpoint_username="{1,20}\s{0,100}(?:N\/A|(({domain}[^\\]+)\\+)?({user}[^"\\]+))""",
      """[\s,]sender="{1,20}\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """,\smachine_ip="{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{0,100}",\s""",
      """,\sdestination_ip="{1,20}(?:N\/A|null\s{0,100}|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\s{0,100}"{0,20}
```