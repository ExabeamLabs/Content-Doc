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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """({host}[\w\-.]{1,2000}) CEF:""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[\w\-.]{1,2000})""",
    """\scs2=\[?(({domain}[^\\=]{1,2000})\\+)?({db_user}[^\],\s]{1,2000})""",
    """\Wsuser=\[?({user}[^\[\]\s]{1,2000})""",
    """\Wshost=\[?({src_host}[\w\-.]{1,2000})""",
    """\scs4=\{applicativeTables:\[({table_name}[^\],]{1,2000})""",
    """\ssrc=\[?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=\[?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """CounterBreach\|([^|]{1,2000}\|){2}({alert_name}[^|]{1,2000})""",
    """\smsg=({additional_info}.+?)\s\w+=""",
    """\scat=({alert_type}.+?)\s\w+=""",
    """CounterBreach\|([^|]{1,2000}\|){3}({alert_severity}[^|]{1,2000})""",
    """\scs3=(\[\\*)?(?:|({malware_url}.+?))\]?\s{0,100}\w+=""",
    """\|File\|.+?\scs3=(\[\\*)?([^\\]{1,2000}\\+)*(?: |({file_name}.+?))\]?\s{0,100}\w+=""",
    """\sact=(?:|({outcome}.+?))\s\w+=""",
    """\scs5=({response_size}\d{1,100})""",
    """\sdhost=({dest_host}[^\s]{1,2000})""",
  ]
  DupFields = [ "db_user->account" ]
}
```