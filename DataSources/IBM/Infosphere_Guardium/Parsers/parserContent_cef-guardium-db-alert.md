#### Parser Content
```Java
{
Name = cef-guardium-db-alert
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Splunk
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|IBM|Guardium|""", """cs3Label=Classification""", """Alert|""" ]
  Fields = [
    """\|rt=({time}\d{1,100})""",
    """exabeam_host=({host}[^\s]+)""",
    """\ssuser=(:\w+=)?(?:|({user}.+?))\s{0,100}\w+=""",
    """\sduser=([^\\=]+\\+)?(?:|({db_user}.+?))\s{0,100}\w+=""",
    """\scs2=({server_group}.+?)\s{0,100}\w+=""",
    """\ssrc=(?!0\.0\.0\.0)({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=(?!0\.0\.0\.0)({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """CEF.+?([^|]+\|){5}[\s-]*({alert_name}.+?)[\s-]*(Alert)?\s{0,100}\|""",
    """CEF.+?([^|]+\|){6}({alert_severity}[^|]+)"""
  ]
  DupFields = [ "alert_name->alert_type", "db_user->account" ]
}
```