#### Parser Content
```Java
{
Name = foxt-file-remove
  Vendor = HelpSystems
  Product = Powertech Identity Access Manager (BoKs)
  Lms = Exabeam
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "sshftl_remove_ok", "Successful sftp remove of file" ]
  Fields = [
    """clientTime="{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z"{0,20}""",
    """\d\dZ\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}sftp - sshftl_remove_ok""",
    """user="{0,20}({user}[^"]{1,2000})"""",
    """Successful sftp remove of file ({file_path}.+?) from """,
    """Successful sftp remove of file (?:({file_parent}(\/[^\/]{1,2000})*\/))?({file_name}[^\/.]{1,2000}\.?({file_ext}[^\/]{0,2000})) from """,
    """fromhost="{0,20}({src_ip}[^"]{1,2000})"""",
    """({event_code}sshftl_remove_ok)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```