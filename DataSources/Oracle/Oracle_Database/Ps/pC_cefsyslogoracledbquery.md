#### Parser Content
```Java
{
Name = cef-syslog-oracle-db-query
    Vendor = Oracle
  Product = Oracle Database
    Lms = ArcSight
    DataType = "database-query"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """|ORACLE|""", """|SELECT|""", """DBID:""" ]
    Fields = [ """\srt=({time}\d{1,100})""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\seventId=({event_code}\d{1,100})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdhost=({src_host}[^\s]{1,2000})""",
      """\ssuser=({user}.+?)\s{1,100}\w+=""",  
      """\sduser=(\/|({account}.+?))\s{1,100}\w+=""",
      """Oracle Audit.+?(OS$USERID|CLIENT USER):\[\d{1,100}\]\s{0,100}("|')({user}[^\\\/\s"']{1,2000})""",
      """Oracle Audit.+?\s(USERID|DATABASE USER):\[\d{1,100}\]\s{0,100}("|')({account}[^\\\/\s"']{1,2000})""",
      """Oracle Audit.+?DBID:\[\d{1,100}\]\s{0,100}("|')(|({database_name}[^"']{1,2000}))("|')""",
      """\|ORACLE\|ORACLESYSDBA\|([^\|]{0,2000}\|){2}({db_operation}[^\|]{1,2000})""",
      """\|ORACLE\|Oracle\|([^\|]{0,2000}\|){3}({db_operation}[^\|]{1,2000})"""
      """\smsg=\s{0,100}({db_query}([^\\=]|(\\\\)*\\=|\\)+?)\s{1,100}(\w+=|$)""",
    ]
    DupFields = ["host->dest_host", "account->db_user"]
  

}
```