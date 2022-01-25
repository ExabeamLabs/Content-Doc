#### Parser Content
```Java
{
Name = cef-syslog-oracle-db-login
    Vendor = Oracle
  Product = Oracle DB
    Lms = ArcSight
    DataType = "database-login"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """|ORACLE|Oracle|""", """|LOGON|""" ]
    Fields = [ """\srt=({time}\d{1,100})""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\seventId=({event_code}\d{1,100})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdhost=({src_host}[^\s]{1,2000})""",
      """\ssuser=({user}.+?)\s{1,100}\w+=""",  
      """\sduser=(\/|({account}.+?))\s{1,100}\w+=""",
      """Oracle Audit.+?OS$USERID:\[\d{1,100}\]\s{0,100}("|')({user}\d{1,100})"""
      """Oracle Audit.+?\sUSERID:\[\d{1,100}\]\s{0,100}("|')({account}\d{1,100})"""
      """Oracle Audit.+?DBID:\[\d{1,100}\]\s{0,100}("|')({database_name}\d{1,100})"""
    ]
    DupFields = ["host->dest_host", "account->db_user"]
  

}
```