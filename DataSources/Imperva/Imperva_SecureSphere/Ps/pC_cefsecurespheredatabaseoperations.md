#### Parser Content
```Java
{
Name = cef-securesphere-database-operations
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = ArcSight
  DataType = "database-update"
  TimeFormat = "epoch"
  Conditions = [ """CEF""", """|SecureSphere|""", """|Audit.DAM|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """eventId=({alert_id}\d{1,100})""",
    """cs2=({src_host}[^\s=]{1,2000}?)\s\w+=""",
    """\Wrt=({time}\d{1,100})""",
    """cs1=({app}[^=]{1,2000}?)\s\w+""",
    """deviceSeverity=({alert_severity}[^\s=]{1,2000}?)\s\w+="""
    """cs3=({database_name}[^=]{1,2000}?)\s\w+=""",
    """cs4=(N\/A\s\()?({db_operation}\w+)""",
    """cs4=(N\/A\s{0,100}\(login\)|({db_query}.+?)\s\w+=)""",
    """ahost=({host}[^\s=]{1,2000}?)\s\w+=""",
    """src=({src_ip}[A-Fa-f.:\d]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f.:\d]{1,2000})""",
    """dhost=({dest_host}.+?)\s\w+=""",
    """spt=({src_port}\d{1,100})""",
    """dpt=({dest_port}\d{1,100})""",
    """cat=({service_name}[^=]{1,2000}?)\s\w+=""",
    """\Wduser=(({domain}[^\\\s@]{1,2000})\\+)?({user}[^\\\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """proto=({protocol}[^\s=]{1,2000}?)\s\w+=""",
    ]


}
```