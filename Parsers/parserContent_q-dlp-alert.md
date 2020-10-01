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
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_endTime=({time}\d+)""",
      """\s({host}[\w.\-]+)\s+LEEF:""",
      """\|incidentID=({alert_id}\d+)""",
      """\|Symantec\|DLP\|({alert_severity}[^\|]+)\|""",
      """\|Symantec\|DLP\|.+?\|({alert_name}.+?)\s*\|""",
      """\|usrName=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({user_email}[^\|@]+@[^\|@]+)|(N/A|({user}[^\|]+)))""",
      """\|suser=((NT AUTHORITY|({domain}[^\|\\\/]+))[\\\/]+)?(system|N/A|({user}[^\|\\\/]+))\|"""
      """\|usrName=(N/A|({user}[^\|@]+))@""",
      """\|usrName=(?=[\w.]+@[\w.])({sender}[^\|]+).+?subject=(?!FTP|HTTP|HTTPS|SFTP|TCP)""",
      """\|duser=(?=[\w.]+@[\w.])({recipients}[^\|]+).+?subject=(?!FTP|HTTP|HTTPS|SFTP|TCP)""",
      """\|duser=(?=[\w.]+@[\w.])({external_address}[^,\|]+).+?subject=(?!FTP|HTTP|HTTPS|SFTP|TCP)""",
      """\|duser=[^@]+@({external_domain}[^,\|]+).+?subject=(?!FTP|HTTP|HTTPS|SFTP|TCP)""",
      """\|subject=((?!SFTP|HTTP|FTP|TCP|N/A)({subject}[^\|]+))""",
      """\|rules=\s*({alert_type}[^\|]+?)\s*\|""",
      """\|duser=({account}.+?)@({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|.+?\|subject=({protocol}FTP)""",
      """\|subject=FTP\s+({file_name}.+?)\s+\(({bytes_num}\d+)\s+({bytes_unit}[^\)]+)""",
      """\|duser=({target}[^\|]+)\|.+?\|subject=({protocol}HTTP)""",
      """\|duser=\w+:\/+[^\s]*?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))(\/|\|).+?\|subject=HTTP""",
      """\|subject=({protocol}TCP:Pop3|SFTP)\|""",
      """\|Protocol=.+?({protocol}SMTP|FTP|HTTP|HTTPS)\|""",
      """\|fileName=(N\/A|({file_name}[^\|]+))""",
      """\|parentPath=(N\/A|({file_path}[^\|]+))""",
      """\|blocked=(None|({outcome}.+?))\s*\|""",
      """({direction}o)"""
    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "src_ip->dlpDeviceName", "file_name->dlpFileName", "outcome->dlpActionTaken", "subject->emailSubject","sender->emailFrom", "recipients->emailTo"]
      NameTemplate = """Symantec DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```