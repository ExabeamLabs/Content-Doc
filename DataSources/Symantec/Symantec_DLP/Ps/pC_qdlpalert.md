#### Parser Content
```Java
{
Name = q-dlp-alert
    Vendor = Symantec
    Product = Symantec DLP
    Lms = QRadar
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "LEEF:", "|Symantec|DLP|", "|subject=" ]
    Fields = [
      """exabeam_endTime=({time}\d{1,100})""",
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\s({host}[\w.\-]{1,2000})\s{1,100}LEEF:""",
      """\|incidentID=({alert_id}\d{1,100})""",
      """\|Symantec\|DLP\|({alert_severity}[^\|]{1,2000})\|""",
      """\|Symantec\|DLP\|[^|]{1,2000}?\|({alert_name}[^|]{1,2000}?)\s{0,100}\|""",
      """\|usrName=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({user_email}[^\|@]{1,2000}@[^\|@]{1,2000})|(N/A|({user}[^\|]{1,2000})))""",
      """\|suser=((NT AUTHORITY|({domain}[^\|\\\/]{1,2000}))[\\\/]{1,2000})?(system|N/A|({user}[^\|\\\/]{1,2000}))\|"""
      """\|usrName=(N/A|({user}[^\|@]{1,2000}))@""",
      """\|usrName=(?=[\w.]{1,2000}@[\w.])({sender}[^\|]{1,2000})""",
      """\|duser=(?=[\w.]{1,2000}@[\w.])({recipients}[^\|]{1,2000})""",
      """\|duser=(?=[\w.]{1,2000}@[\w.])({external_address}[^,\|]{1,2000})""",
      """\|duser=[^@]{1,2000}@({external_domain}[^,\\|]{1,2000})\s{0,100}[\|,]""",
      """\|subject=\s{0,100}((?!SFTP|HTTP|FTP|TCP|N/A)({subject}[^\|]{1,2000}?))\s{0,100}\|""",
      """\|rules=\s{0,100}({alert_type}[^\|]{1,2000}?)\s{0,100}\|""",
      """\|duser=({account}.+?)@({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|[^|]{1,2000}?\|subject=({protocol}FTP)""",
      """\|subject=FTP\s{1,100}({file_name}.+?)\s{1,100}\(({bytes_num}\d{1,100})\s{1,100}({bytes_unit}[^\)]{1,2000})""",
      """\|duser=({target}[^\|]{1,2000})\|[^|]{1,2000}?\|subject=({protocol}HTTP)""",
      """\|duser=\w+:\/+[^\s]{0,2000}?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]{1,2000}(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))(\/|\|)[^|]{1,2000}?\|subject=HTTP""",
      """\|subject=({protocol}TCP:Pop3|SFTP)\|""",
      """\|Protocol=.+?({protocol}SMTP|FTP|HTTP|HTTPS)\|""",
      """\|fileName=(N\/A|({file_name}[^\|]{1,2000}))""",
      """\|parentPath=(N\/A|({file_path}[^\|]{1,2000}))""",
      """\|blocked=(None|({outcome}[^\|]{1,2000}?))\s{0,100}\|""",
    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "src_ip->dlpDeviceName", "file_name->dlpFileName", "outcome->dlpActionTaken", "subject->emailSubject","sender->emailFrom", "recipients->emailTo"]
      NameTemplate = """Symantec DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```