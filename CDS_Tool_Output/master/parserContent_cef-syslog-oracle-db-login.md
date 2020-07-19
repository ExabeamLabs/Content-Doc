#### Parser Content
```Java
{
Name = cef-syslog-oracle-db-login
    Vendor = Oracle
    Lms = ArcSight
    DataType = "database-login"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """|ORACLE|Oracle|""", """|LOGON|""" ]
    Fields = [ """\srt=({time}\d+)""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]+)""",
      """\seventId=({event_code}\d+)""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdhost=({src_host}[^\s]+)""",
      """\ssuser=({user}.+?)\s+\w+=""",  
      """\sduser=(\/|({account}.+?))\s+\w+=""",
      """Oracle Audit.+?OS$USERID:\[\d+\]\s*("|')({user}\d+)"""
      """Oracle Audit.+?\sUSERID:\[\d+\]\s*("|')({account}\d+)"""
      """Oracle Audit.+?DBID:\[\d+\]\s*("|')({database_name}\d+)"""
    ]
    DupFields = ["host->dest_host", "account->db_user"]
  }
```