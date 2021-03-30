#### Parser Content
```Java
{
Name = s-microsoft-database-login
  Vendor = Microsoft
  Product = SQL Server
  Lms = Splunk
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [""", instance_name=""",""", account_name=""",""", client_name=""",""", application_name="""]
  Fields = [
      """\sinstance_name="({additional_info}[^"]+)""",
      """\saccount_name="(({domain}[^\\\/"]+?)[\\\/]+)?({user}[^\\\/"]+?)\s*"""",
      """\sclient_name="({src_host}[^"]+)""",
      """\sapplication_name="({app}[^"]+)""",
      """\sdatabase_name="({database_name}[^"]+)""",
      """\serr_desc="({outcome}[^"]+)""",
      """\sfirst_login="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
      """exabeam_host=({host}[\w.\-]+)""",
    ]
}
```