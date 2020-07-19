#### Parser Content
```Java
{
Name = cef-syslog-oracle-db-query
    Vendor = Oracle
    Lms = ArcSight
    DataType = "database-query"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """|ORACLE|""", """|SELECT|""", """DBID:""" ]
    Fields = [ """\srt=({time}\d+)""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]+)""",
      """\seventId=({event_code}\d+)""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdhost=({src_host}[^\s]+)""",
      """\ssuser=({user}.+?)\s+\w+=""",  
      """\sduser=(\/|({account}.+?))\s+\w+=""",
      """Oracle Audit.+?(OS$USERID|CLIENT USER):\[\d+\]\s*("|')({user}[^\\\/\s"']+)""",
      """Oracle Audit.+?\s(USERID|DATABASE USER):\[\d+\]\s*("|')({account}[^\\\/\s"']+)""",
      """Oracle Audit.+?DBID:\[\d+\]\s*("|')(|({database_name}[^"']+))("|')""",
      """\|ORACLE\|ORACLESYSDBA\|([^\|]*\|){2}({db_operation}[^\|]+)""",
      """\|ORACLE\|Oracle\|([^\|]*\|){3}({db_operation}[^\|]+)"""
      """\smsg=\s*({db_query}([^\\=]|(\\\\)*\\=|\\)+?)\s+(\w+=|$)""",
    ]
    DupFields = ["host->dest_host", "account->db_user"]
  }
```