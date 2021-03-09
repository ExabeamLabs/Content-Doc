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
      """({host}[\w\.-]+)\s+incident_id""",
      """[\s,]incident_id="+({alert_id}\d+)""",
      """[\s,]blocked="+(None|({outcome}[^"]+?))"""",
      """[\s,]policy="+({alert_name}[^"]+?)"""",
      """[\s,]occurred_on="+({occured_time}[^"]+?)"""",
      """[\s,]reported_on="+({reported_time}[^"]+?)"""",
      """[\s,]policy="+({alert_type}[^"]+?)"""",
      """[\s,]rules=(?:"+)?\s*({alert_type}[^="]+?)\s*(?:"+)?,\s\w+=""",
      """[\s,]severity="+({alert_severity}[^"]+?)"""",
      """[\s,]sender="+\s*({sender}[^\s"@,]+@[^\s"@,]+?)"""",
      """,\sendpoint_username="+\s*(?:N\/A|(({domain}[^\\]+)\\+)?({user}[^"\\]+))""",
      """[\s,]sender="+\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """,\smachine_ip="+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*",\s""",
      """,\sdestination_ip="+(?:N\/A|null\s*|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\s*"*,\s""",
      """[\s,]recipients="+\s*(?:N\/A|Unknown|({target}[^",]+?))"*,""",
      """[\s,]recipients="+\s*({recipients}(?:({external_address}[^\s"@,]+@({external_domain}[^\s@",]+?)))(?:\s*,\s*[^\s"@,]+@[^\s@",]+?\s*?)*)\s*"*,""",
      """[\s,]recipients="+\s*(?:[^"\s]*?)({top_domain}(?!(?:\d+\.){3}\d+)(?:[^\.\s@]+)(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(?::|"|\/)""",
      """[\s,]recipients="+\s*({protocol}\w+):\/\/""",
      """,\sprotocol="+(?:N\/A|({protocol}[^",]+?))\s*"*,""",
      """[\s,]subject="+(?:N\/A|({additional_info}(?:[^",]|"")+?))\s*"*,""",
      """,\sfile_name="+(?:N\/A|({file_name}[^",]+?))\s*"*,""",
      """,\sattachment_filename="+(?:N\/A|({file_name}[^.",]+?(?:\.({file_ext}[^",]+?))?))\s*"*,""",
      """,\sendpoint_machine="+(?:N\/A|({device_id}[^",]+?))\s*"*,\s""",
      """\sZID="+({user}[^",\s]+?)"*,"""
    ]
    DupFields = [ "additional_info->subject", "external_address->recipient", "alert_id->email_id", "sender->user_email" , "file_name->attachment","device_id->src_host"]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "src_ip->dlpDeviceName", "outcome->dlpActionTaken"]
      NameTemplate = """Symantec DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```