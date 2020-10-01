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
    """clientTime="*({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z"*""",
    """\d\dZ\s+({host}[\w\-.]+)\s+sftp - sshftl_remove_ok""",
    """user="*({user}[^"]+)"""",
    """Successful sftp remove of file ({file_path}.+?) from """,
    """Successful sftp remove of file (?:({file_parent}(\/[^\/]+)*\/))?({file_name}[^\/.]+\.?({file_ext}[^\/]*)) from """,
    """fromhost="*({src_ip}[^"]+)"""",
    """({event_code}sshftl_remove_ok)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```