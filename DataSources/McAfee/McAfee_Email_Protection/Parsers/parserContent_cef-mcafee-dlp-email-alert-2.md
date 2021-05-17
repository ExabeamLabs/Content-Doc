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
      """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\|DLP: Email Protection\|({alert_severity}.+?)\|""",
      """(\s|\|)deviceSeverity=({alert_severity}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""", 
      """(\s|\|)shost=({src_host}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
      """(\s|\|)src=({src_ip}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
      """(\s|\|)suser=({user}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
      """(\s|\|)sntdom=({domain}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
      """(\s|\|)sproc=({process_name}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
      """(\s|\|)cs1=({alert_name}.+?)\s{1,100}cs2="""
      """(\s|\|)cs2=.*?({user_email}[^<\s@']{1,2000}?@[^<>\s;']{1,2000}).*?\s{1,100}cs3="""
      """(\s|\|)cs5=Recipients:\s{0,100}'*({recipient}[^;']{1,2000}).*?\s{1,100}Recipients Cc:""",
      """(\s|\|)cs5=Recipients:[^;]{1,2000}?<({recipient}[^>]{1,2000})>.*?Recipients Cc:""",
      """(\s|\|)cs5=Recipients:\s{0,100}({recipients}.+?)\s{1,100}Recipients Cc:""",
      """(\s|\|)cs6=({subject}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
      """(\s|\|)fname=({file_name}[^\.]{1,2000}({file_ext}.+?))\s{1,100}([\w\.-]{1,2000}=|$)""",
      """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
      """(\s|\|)eventId=({alert_id}\d{1,100})\s""",
      """({direction}OUTGOING)_EMAIL"""
      """({alert_type}DLP: Email Protection)"""
      """(\s|\|)act=({outcome}[^=]{1,2000}?)\s{1,100}([\w\.-]{1,2000}=|$)"""
    ]
    DupFields = [ "user_email->sender", "recipient->target", "file_name->attachments"]
}
```