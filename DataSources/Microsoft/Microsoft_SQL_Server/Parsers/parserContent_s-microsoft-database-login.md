#### Parser Content
```Java
{
Name = s-microsoft-database-login
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Splunk
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [""", instance_name=""",""", account_name=""",""", client_name=""",""", application_name="""]
  Fields = [
      """\sinstance_name="({additional_info}[^"]{1,2000})""",
      """\saccount_name="(({domain}[^\\\/"]{1,2000}?)[\\\/]{1,2000})?({user}[^\\\/"]{1,2000}?)\s{0,100}"""",
      """\sclient_name="({src_host}[^"]{1,2000})""",
      """\sapplication_name="({app}[^"]{1,2000})""",
      """\sdatabase_name="({database_name}[^"]{1,2000})""",
      """\serr_desc="({outcome}[^"]{1,2000})""",
      """\sfirst_login="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
    ]
}
```