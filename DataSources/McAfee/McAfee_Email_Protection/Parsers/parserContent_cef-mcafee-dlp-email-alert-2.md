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
      """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]+=|$)""",
      """exabeam_host=({host}[^\s]+)""",
      """\|DLP: Email Protection\|({alert_severity}.+?)\|""",
      """(\s|\|)deviceSeverity=({alert_severity}.+?)\s{1,100}([\w\.-]+=|$)""", 
      """(\s|\|)shost=({src_host}.+?)\s{1,100}([\w\.-]+=|$)""",
      """(\s|\|)src=({src_ip}.+?)\s{1,100}([\w\.-]+=|$)""",
      """(\s|\|)suser=({user}.+?)\s{1,100}([\w\.-]+=|$)""",
      """(\s|\|)sntdom=({domain}.+?)\s{1,100}([\w\.-]+=|$)""",
      """(\s|\|)sproc=({process_name}.+?)\s{1,100}([\w\.-]+=|$)""",
      """(\s|\|)cs1=({alert_name}.+?)\s{1,100}cs2="""
      """(\s|\|)cs2=.*?({user_email}[^<\s@']+?@[^<>\s;']+).*?\s{1,100}cs3="""
      """(\s|\|)cs5=Recipients:\s{0,100}'*({recipient}[^;']+).*?\s{1,100}Recipients Cc:""",
      """(\s|\|)cs5=Recipients:[^;]+?<({recipient}[^>]+)>.*?Recipients Cc:""",
      """(\s|\|)cs5=Recipients:\s{0,100}({recipients}.+?)\s{1,100}Recipients Cc:""",
      """(\s|\|)cs6=({subject}.+?)\s{1,100}([\w\.-]+=|$)""",
      """(\s|\|)fname=({file_name}[^\.]+({file_ext}.+?))\s{1,100}([\w\.-]+=|$)""",
      """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]+=|$)""",
      """(\s|\|)eventId=({alert_id}\d{1,100})\s""",
      """({direction}OUTGOING)_EMAIL"""
      """({alert_type}DLP: Email Protection)"""
      """(\s|\|)act=({outcome}[^=]+?)\s{1,100}([\w\.-]+=|$)"""
    ]
    DupFields = [ "user_email->sender", "recipient->target", "file_name->attachments"]
}
```