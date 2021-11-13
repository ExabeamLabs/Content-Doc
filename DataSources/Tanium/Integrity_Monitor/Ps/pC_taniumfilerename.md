#### Parser Content
```Java
{
Name = tanium-file-rename
  DataType = "file-write"
  Conditions = [ """ Tanium """, """ Computer-Name ="""", """ Process-Path="""", """ File-Path="""", """Change-Type="RenamePath"""" ]
  Fields = ${TaniumParserTemplates.tanium-file-operations.Fields}[
    """({accesses}RenamePath)"""
   ]

tanium-file-operations = {
  Vendor = Tanium
  Product = Integrity Monitor
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}\+?\-?\d\d:\d\d)\s{1,100}({host}[^\s]{1,2000})\s{1,100}Tanium""",
    """\sUser="({user}[^"]{1,2000})"""",
    """Computer-Name ="({dest_host}[^"]{1,2000})"""",
    """File-Path="({file_path}({file_parent}[^"]{1,2000}\\)({file_name}[^"]{1,2000}\.({file_ext}[^"]{1,2000})))""",
    """Process-Path="({process}[^"]{1,2000}(\\|\/)({process_name}[^"]{1,2000}))"""",
    """File-Path="(|({file_path}[^=]{1,2000}?))"\s\w{1,2000}="""
  
}
```