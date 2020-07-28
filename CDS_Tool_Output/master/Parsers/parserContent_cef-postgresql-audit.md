#### Parser Content
```Java
{
Name = cef-postgresql-audit
  Vendor = PostgreSQL
  Product = PostgreSQL
  Lms = Direct
  DataType = "database-access"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """eventId=""", """|PostgreSQL|PostgreSQL Audit|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\srt=({time}.+?)\s*\w+=""",
    """\scs2=(None|idle|idle\sin\stransaction|authentication|({db_query}.+?))\s*\w+=""",
    """\scs3=(\[unknown\]|({db_user}.+?))\s*\w+=""",
    """\scs4=((\[unknown\])|({database_name}.+?))\s*\w+=""",
    """\scs6=\s*({additional_info}.+?)\s*\w+=""",
    """\sshost=({src_host}.+?)\s*\w+=""",
    """\sdvc=({host}[A-Fa-f:\d.]+)""",
    """\sdvchost=({host}[\w\-.]+)""",
    """CEF[^\|]+\|([^\|]*\|){4}({event_name}.+?)\s*\|""",
    """\sdtz=({dtz}.+?)\s*\w+=""",
    """\sact=({action}.+?)\s*\w+=""",
    """\seventId=({alert_id}.+?)\s*\w+=""",
    """\ssuser=(N\/A|-|\[unknown\]|({user}.+?))\s*\w+=""",
    """\ssrc=({src_ip}.+?)\s*\w+=""",
  ] 
}

{ 
  Name = ping-web-activity
  Vendor = Ping Identity
  Product = PingAccess
  DataType ="web-activity"
  Lms = Direct
  TimeFormat = "yyyy-mm-dd'T'HH:mm:ss"
  Conditions = [ """<<Custom condition cont-8024>>""" ] 
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+)(,\d+)?\|\s*({id}[^\|]+)?\|\s*({transcation_id}[^\|]+)?\|\s*([^\|]+\|){3}\s*({action}[^\|]+)\|\s*({user}[^\|]+)?\|\s*({authentication}[^\|]+)?\|\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?\|\s*({method}[^\|]+)\|\s*({uri_path}[^\|]+)\|({result_code}[^\|]+)\|\s*([^\|]+)\|( |\s*({failure_reason}[^\|]+))\|"""
  ]
}
```