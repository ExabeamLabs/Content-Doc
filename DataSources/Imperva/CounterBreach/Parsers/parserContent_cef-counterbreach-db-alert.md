#### Parser Content
```Java
{
Name = cef-counterbreach-db-alert
  Vendor = Imperva
  Product = CounterBreach
  Lms = ArcSight
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|Imperva Inc.|CounterBreach|""", """=AccessedTables""" ]
  Fields = [
    """start=({time}\d{1,100})""",
    """start=({time}\d{4}\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """({host}[\w\-.]+) CEF:""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[\w\-.]+)""",
    """\scs2=\[?(({domain}[^\\=]+)\\+)?({db_user}[^\],\s]+)""",
    """\Wsuser=\[?({user}[^\[\]\s]+)""",
    """\Wshost=\[?({src_host}[\w\-.]+)""",
    """\scs4=\{applicativeTables:\[({table_name}[^\],]+)""",
    """\ssrc=\[?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=\[?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """CounterBreach\|([^|]+\|){2}({alert_name}[^|]+)""",
    """\smsg=({additional_info}.+?)\s\w+=""",
    """\scat=({alert_type}.+?)\s\w+=""",
    """CounterBreach\|([^|]+\|){3}({alert_severity}[^|]+)""",
    """\scs3=(\[\\*)?(?:|({malware_url}.+?))\]?\s{0,100}\w+=""",
    """\|File\|.+?\scs3=(\[\\*)?([^\\]+\\+)*(?: |({file_name}.+?))\]?\s{0,100}\w+=""",
    """\sact=(?:|({outcome}.+?))\s\w+=""",
    """\scs5=({response_size}\d{1,100})""",
    """\sdhost=({dest_host}[^\s]+)""",
  ]
  DupFields = [ "db_user->account" ]
}
```