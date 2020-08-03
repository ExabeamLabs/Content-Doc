#### Parser Content
```Java
{
Name = cef-mcafee-dlp-email-alert-2
    Vendor = McAfee
    Product = McAfee Email Protection
    Lms = ArcSight
    DataType = "dlp-email-alert"
    TimeFormat = "epoch"
    Conditions = [ """McAfee|Data Loss Prevention""", """|DLP: Email Protection|""" ]
    Fields = [
      """(\s|\|)rt=({time}.+?)\s+([\w\.-]+=|$)""",
      """exabeam_host=({host}[^\s]+)""",
      """\|DLP: Email Protection\|({alert_severity}.+?)\|""",
      """(\s|\|)deviceSeverity=({alert_severity}.+?)\s+([\w\.-]+=|$)""", 
      """(\s|\|)shost=({src_host}.+?)\s+([\w\.-]+=|$)""",
      """(\s|\|)src=({src_ip}.+?)\s+([\w\.-]+=|$)""",
      """(\s|\|)suser=({user}.+?)\s+([\w\.-]+=|$)""",
      """(\s|\|)sntdom=({domain}.+?)\s+([\w\.-]+=|$)""",
      """(\s|\|)sproc=({process_name}.+?)\s+([\w\.-]+=|$)""",
      """(\s|\|)cs1=({alert_name}.+?)\s+cs2="""
      """(\s|\|)cs2=.*?({user_email}[^<\s@']+?@[^<>\s;']+).*?\s+cs3="""
      """(\s|\|)cs5=Recipients:\s*'*({recipient}[^;']+).*?\s+Recipients Cc:""",
      """(\s|\|)cs5=Recipients:[^;]+?<({recipient}[^>]+)>.*?Recipients Cc:""",
      """(\s|\|)cs5=Recipients:\s*({recipients}.+?)\s+Recipients Cc:""",
      """(\s|\|)cs6=({subject}.+?)\s+([\w\.-]+=|$)""",
      """(\s|\|)fname=({file_name}.+?)\s+([\w\.-]+=|$)""",
      """(\s|\|)fsize=({bytes}.+?)\s+([\w\.-]+=|$)""",
      """(\s|\|)eventId=({alert_id}\d+)\s""",
      """({direction}OUTGOING)_EMAIL"""
      """({alert_type}DLP: Email Protection)"""
      """(\s|\|)act=({outcome}[^=]+?)\s+([\w\.-]+=|$)"""
    ]
    DupFields = [ "user_email->sender", "recipient->target", "file_name->attachments"]
}
```