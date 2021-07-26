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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\ssuser=(:\w+=)?(?:|({user}.+?))\s{0,100}\w+=""",
    """\sduser=([^\\=]{1,2000}\\+)?(?:|({db_user}.+?))\s{0,100}\w+=""",
    """\scs2=({server_group}.+?)\s{0,100}\w+=""",
    """\ssrc=(?!0\.0\.0\.0)({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=(?!0\.0\.0\.0)({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """CEF.+?([^|]{1,2000}\|){5}[\s-]{0,2000}({alert_name}.+?)[\s-]{0,2000}(Alert)?\s{0,100}\|""",
    """CEF.+?([^|]{1,2000}\|){6}({alert_severity}[^|]{1,2000})"""
  ]
  DupFields = [ "alert_name->alert_type", "db_user->account" ]
}
```