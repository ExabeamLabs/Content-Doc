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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\srt=({time}.+?)\s{0,100}\w+=""",
    """\scs2=(None|idle|idle\sin\stransaction|authentication|({db_query}.+?))\s{0,100}\w+=""",
    """\scs3=(\[unknown\]|({db_user}.+?))\s{0,100}\w+=""",
    """\scs4=((\[unknown\])|({database_name}.+?))\s{0,100}\w+=""",
    """\scs6=\s{0,100}({additional_info}.+?)\s{0,100}\w+=""",
    """\sshost=({src_host}.+?)\s{0,100}\w+=""",
    """\sdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\sdvchost=({host}[\w\-.]{1,2000})""",
    """CEF[^\|]{1,2000}\|([^\|]{0,2000}\|){4}({event_name}.+?)\s{0,100}\|""",
    """\sdtz=({dtz}.+?)\s{0,100}\w+=""",
    """\sact=({action}.+?)\s{0,100}\w+=""",
    """\seventId=({alert_id}.+?)\s{0,100}\w+=""",
    """\ssuser=(N\/A|-|\[unknown\]|({user}.+?))\s{0,100}\w+=""",
    """\ssrc=({src_ip}.+?)\s{0,100}\w+=""",
  ] 
}
```